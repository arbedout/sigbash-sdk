/**
 * Shared wallet execution credential: one non-human pseudonymous protocol
 * principal per wallet/execution domain for the design-partner beta.
 *
 * The principal is an ordinary SDK credential triplet (apiKey, userKey,
 * userSecretKey) that rides the single-owner PolicyKey/KMC protocol path
 * unchanged: authHash = DSHA256(apiKey || userKey) is the server-visible
 * principal, the Ed25519 PoP key derives from userSecretKey exactly as for
 * any SDK credential, and the KMC KEK schedule is untouched. The only thing
 * that makes it a shared execution credential is how the wallet-domain
 * components come into existence: they are DERIVED, once per wallet, from
 * the wallet capability group's founding (epoch 1) key. Every authorized
 * client holding that epoch key derives the byte-identical triplet, so
 * two application users converge on the same principal without any
 * distribution step, and the triplet's only persistence is the capability
 * encrypted state the epoch key already lives in.
 *
 * Beta posture. This credential class is Signet-only by construction: a
 * removed user who copied the shared secret cannot be made to forget it,
 * so removal stops future vault-epoch access through the capability
 * rotation path but not possession. Revocable per-principal PolicyKey
 * access is the mainnet replacement. Every construction and parse here
 * fails closed on any network other than signet; there is no toggle.
 *
 * Key-schedule registry. HKDF info labels live under the
 * `sigbash.executioncredential.v1/*` prefix, disjoint from the user-root
 * (`sigbash.userroot.v1.*`), capability (`sigbash.capability.v1.*`), and
 * PoP (`sigbash/sdk-pop-ed25519/v1`) label spaces; the label set is pinned
 * by the execution-credential suite. The salt binds the wallet client id,
 * so the derived principal is unique per wallet/execution domain and never
 * reuses another domain's material.
 *
 * 2FA separation. The derived userSecretKey shares no material with the
 * human application TOTP domain or the SDK key TOTP domain; this module
 * never touches TOTP secrets, and institutional keys created under a
 * shared execution credential are registered with two-factor prompts
 * disabled (a shared TOTP would be a shared human-style factor).
 */

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  utf8,
} from '../contracts/encoding';
import { ExecutionCredentialError } from './executionCredentialErrors';
import { derivePopKey } from '../pop';

/** Wire/format version of the canonical in-memory serialization. */
export const EXECUTION_CREDENTIAL_FORMAT_VERSION = 1;

/** The only network this credential class is valid on. */
export const EXECUTION_CREDENTIAL_NETWORK = 'signet' as const;

/**
 * Self-identifying magic prefix of the canonical serialization. The letters
 * G and X are outside the hexadecimal alphabet, so the token cannot occur
 * in the hex encoding of unrelated ciphertext — it is chosen to be safe as
 * a prohibited-plaintext scan marker on byte surfaces.
 */
export const EXECUTION_CREDENTIAL_MAGIC = 'SIGAEXEC1';

/**
 * Network code inside the serialization; signet is the only accepted value
 * and every other code fails closed on parse.
 */
export const EXECUTION_CREDENTIAL_NETWORK_CODE = 0x02;

/** HKDF info labels; the wallet client id is bound as the HKDF salt. */
export const EXECUTION_CREDENTIAL_HKDF_PREFIX = 'sigbash.executioncredential.v1';
const USER_KEY_HKDF_INFO = utf8(`${EXECUTION_CREDENTIAL_HKDF_PREFIX}/user-key`);
const USER_SECRET_HKDF_INFO = utf8(`${EXECUTION_CREDENTIAL_HKDF_PREFIX}/user-secret`);

/** One derived shared execution credential for one wallet domain. */
export interface WalletExecutionCredentialV1 {
  readonly formatVersion: number;
  /** Organization protocol apiKey; every SDK principal of the org shares it. */
  readonly orgApiKey: string;
  /** Wallet-domain user key (64 lowercase hex chars). */
  readonly userKey: string;
  /** Wallet-domain user secret (64 lowercase hex chars). */
  readonly userSecretKey: string;
  /** Opaque wallet client id (lowercase UUID) the principal is bound to. */
  readonly walletClientIdHex: string;
  /** Always 'signet'; construction fails closed on anything else. */
  readonly network: typeof EXECUTION_CREDENTIAL_NETWORK;
}

/** Public (non-secret) registration material for the principal. */
export interface ExecutionCredentialPublicMaterial {
  /** DSHA256(apiKey || userKey) — the server-visible pseudonymous principal. */
  readonly authHashHex: string;
  /** Wallet-domain user key; the admin registration path needs it. */
  readonly userKeyHex: string;
  /** Hex Ed25519 PoP public key derived from the wallet-domain secret. */
  readonly popPublicKeyHex: string;
  readonly walletClientIdHex: string;
  readonly network: typeof EXECUTION_CREDENTIAL_NETWORK;
}

const HEX_64 = /^[0-9a-f]{64}$/;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function assertOrgApiKey(orgApiKey: string): void {
  if (!HEX_64.test(orgApiKey)) {
    throw new ExecutionCredentialError('org-api-key-malformed');
  }
}

function assertWalletClientId(walletClientIdHex: string): void {
  if (!UUID_RE.test(walletClientIdHex)) {
    throw new ExecutionCredentialError('wallet-client-id-malformed');
  }
}

function assertEpochKey(epochKeyBytes: Uint8Array): void {
  if (epochKeyBytes.length !== 32) {
    throw new ExecutionCredentialError('epoch-key-malformed');
  }
}

function assertSignet(network: string): void {
  if (network !== EXECUTION_CREDENTIAL_NETWORK) {
    // Fail closed without echoing the rejected network value.
    throw new ExecutionCredentialError('network-not-signet');
  }
}

function hkdf32(info: Uint8Array, epochKeyBytes: Uint8Array, walletClientIdHex: string): Uint8Array {
  return hkdf(sha256, Uint8Array.from(epochKeyBytes), utf8(walletClientIdHex), info, 32);
}

/**
 * Derive the shared execution credential for one wallet/execution domain.
 * Deterministic in (orgApiKey, founding epoch key, wallet client id): every
 * authorized client derives the identical triplet from the same inputs.
 */
export function deriveWalletExecutionCredential(
  orgApiKey: string,
  walletGroupEpoch1KeyBytes: Uint8Array,
  walletClientIdHex: string,
): WalletExecutionCredentialV1 {
  assertOrgApiKey(orgApiKey);
  assertEpochKey(walletGroupEpoch1KeyBytes);
  assertWalletClientId(walletClientIdHex);

  const walletClientId = walletClientIdHex.toLowerCase();
  const userKey = bytesToHex(hkdf32(USER_KEY_HKDF_INFO, walletGroupEpoch1KeyBytes, walletClientId));
  const userSecretKey = bytesToHex(hkdf32(USER_SECRET_HKDF_INFO, walletGroupEpoch1KeyBytes, walletClientId));

  return {
    formatVersion: EXECUTION_CREDENTIAL_FORMAT_VERSION,
    orgApiKey,
    userKey,
    userSecretKey,
    walletClientIdHex: walletClientId,
    network: EXECUTION_CREDENTIAL_NETWORK,
  };
}

/**
 * Double SHA256 over the UTF-8 concatenation, matching the SDK's auth-hash
 * definition. Synchronous form for callers that cannot await.
 */
export function executionCredentialAuthHash(orgApiKey: string, userKey: string): string {
  assertOrgApiKey(orgApiKey);
  if (!HEX_64.test(userKey)) {
    throw new ExecutionCredentialError('user-key-malformed');
  }
  const inner = sha256(utf8(orgApiKey + userKey));
  return bytesToHex(sha256(inner));
}

/**
 * Public registration material including the PoP public key. The PoP key
 * derives from the wallet-domain secret exactly as for any SDK credential,
 * via the shared pop module. The secret itself never appears in the result.
 */
export async function executionCredentialRegistrationMaterial(
  credential: WalletExecutionCredentialV1,
): Promise<ExecutionCredentialPublicMaterial> {
  const popKey = await derivePopKey(credential.userSecretKey);
  return {
    authHashHex: executionCredentialAuthHash(credential.orgApiKey, credential.userKey),
    userKeyHex: credential.userKey,
    popPublicKeyHex: popKey.publicKeyHex,
    walletClientIdHex: credential.walletClientIdHex,
    network: credential.network,
  };
}

function uuidToBytes(walletClientIdHex: string): Uint8Array {
  return hexToBytes(walletClientIdHex.replace(/-/g, ''));
}

function bytesToUuid(bytes: Uint8Array): string {
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Canonical in-memory serialization. Layout:
 *   magic 'SIGAEXEC1' (9 bytes)
 *   format version (u8)
 *   orgApiKey (32 bytes, from hex)
 *   userKey (32 bytes, from hex)
 *   userSecretKey (32 bytes, from hex)
 *   wallet client id (16 bytes, UUID octets)
 *   network code (u8; signet only)
 *
 * The serialization exists for memory transit into the vault and for the
 * golden vectors; it is never a persistence or wire format — plaintext
 * credentials are not persisted anywhere and the vault is memory-only.
 */
export function serializeWalletExecutionCredential(
  credential: WalletExecutionCredentialV1,
): Uint8Array {
  if (credential.formatVersion !== EXECUTION_CREDENTIAL_FORMAT_VERSION) {
    throw new ExecutionCredentialError('format-unsupported');
  }
  assertOrgApiKey(credential.orgApiKey);
  if (!HEX_64.test(credential.userKey) || !HEX_64.test(credential.userSecretKey)) {
    throw new ExecutionCredentialError('credential-malformed');
  }
  assertWalletClientId(credential.walletClientIdHex);
  assertSignet(credential.network);

  return concatBytes(
    utf8(EXECUTION_CREDENTIAL_MAGIC),
    new Uint8Array([EXECUTION_CREDENTIAL_FORMAT_VERSION]),
    hexToBytes(credential.orgApiKey),
    hexToBytes(credential.userKey),
    hexToBytes(credential.userSecretKey),
    uuidToBytes(credential.walletClientIdHex),
    new Uint8Array([EXECUTION_CREDENTIAL_NETWORK_CODE]),
  );
}

/**
 * Parse a canonical serialization. Every deviation — wrong magic, unknown
 * format version, malformed field, non-signet network code, wrong length —
 * fails closed with a typed error.
 */
export function parseWalletExecutionCredential(bytes: Uint8Array): WalletExecutionCredentialV1 {
  const magic = utf8(EXECUTION_CREDENTIAL_MAGIC);
  const totalLength = magic.length + 1 + 32 + 32 + 32 + 16 + 1;
  if (bytes.length !== totalLength) {
    throw new ExecutionCredentialError('credential-malformed');
  }
  for (let i = 0; i < magic.length; i++) {
    if (bytes[i] !== magic[i]) {
      throw new ExecutionCredentialError('credential-malformed');
    }
  }
  let offset = magic.length;
  const formatVersion = bytes[offset++];
  if (formatVersion !== EXECUTION_CREDENTIAL_FORMAT_VERSION) {
    throw new ExecutionCredentialError('format-unsupported');
  }
  const orgApiKey = bytesToHex(bytes.slice(offset, offset + 32));
  offset += 32;
  const userKey = bytesToHex(bytes.slice(offset, offset + 32));
  offset += 32;
  const userSecretKey = bytesToHex(bytes.slice(offset, offset + 32));
  offset += 32;
  const walletClientIdHex = bytesToUuid(bytes.slice(offset, offset + 16));
  offset += 16;
  const networkCode = bytes[offset++];
  if (networkCode !== EXECUTION_CREDENTIAL_NETWORK_CODE) {
    // Fail closed without echoing the rejected code.
    throw new ExecutionCredentialError('network-not-signet');
  }
  assertOrgApiKey(orgApiKey);
  assertWalletClientId(walletClientIdHex);
  return {
    formatVersion,
    orgApiKey,
    userKey,
    userSecretKey,
    walletClientIdHex,
    network: EXECUTION_CREDENTIAL_NETWORK,
  };
}

/** Byte-identity helper for callers comparing two derivations. */
export function walletExecutionCredentialsEqual(
  a: WalletExecutionCredentialV1,
  b: WalletExecutionCredentialV1,
): boolean {
  const left = serializeWalletExecutionCredential(a);
  const right = serializeWalletExecutionCredential(b);
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
