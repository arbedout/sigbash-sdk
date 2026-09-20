/**
 * Organization protocol key derivation: the deterministic, zero-issuance
 * source of the organization's protocol credentials for the design-partner
 * Signet beta.
 *
 * Every organization-scoped protocol secret is DERIVED, not issued, from
 * the organization's founding capability state — the org-common capability
 * group's epoch 1 key. Every authorized client holding that epoch key
 * derives byte-identical material, so no distribution step and no
 * plaintext copy ever exists outside the capability encrypted state the
 * epoch key already lives in. Two derivations exist in one family:
 *
 * - the organization protocol apiKey every SDK principal of the
 *   organization shares, and
 * - the organization registration principal (user key + user secret) that
 *   bootstraps the organization's admin row, so a wallet's shared
 *   execution principal is always pre-registered by an admin instead of
 *   ever landing in the admin row itself.
 *
 * Key-schedule registry. HKDF info labels live under the
 * `sigbash.orgprotocol.v1` prefix, disjoint from the wallet execution
 * credential (`sigbash.executioncredential.v1/*`), user-root
 * (`sigbash.userroot.v1.*`), capability (`sigbash.capability.v1.*`), and
 * PoP (`sigbash/sdk-pop-ed25519/v1`) label spaces. The organization client
 * id is bound as the HKDF salt (lowercase canonical UUID form), so two
 * organizations with different identities never derive the same key from
 * comparable material, and case-rendering differences of the same
 * organization id cannot fork the key.
 *
 * Founding-key constraint. The founding (epoch 1) key is the ONLY
 * derivation seed. Deriving from a later epoch would mint a different
 * organization key per client and silently fork the organization's
 * protocol identity, so a missing founding epoch is an error upstream,
 * never a fallback. The org-common group's epoch 1 key must be retained
 * for the organization's lifetime.
 *
 * Inherited beta limitation (accepted by design, do not "fix" here):
 * whoever can read the organization's capability envelope can derive
 * these keys, and organization credential rotation couples to capability
 * epochs.
 */

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8 } from '../contracts/encoding';
import { OrgProtocolKeyError } from './orgProtocolKeyErrors';

/** HKDF info prefix for the organization protocol key family. */
export const ORG_PROTOCOL_KEY_HKDF_PREFIX = 'sigbash.orgprotocol.v1';

const API_KEY_HKDF_INFO = utf8(`${ORG_PROTOCOL_KEY_HKDF_PREFIX}/api-key`);
const REGISTRATION_USER_KEY_HKDF_INFO = utf8(
  `${ORG_PROTOCOL_KEY_HKDF_PREFIX}/registration-user-key`,
);
const REGISTRATION_USER_SECRET_HKDF_INFO = utf8(
  `${ORG_PROTOCOL_KEY_HKDF_PREFIX}/registration-user-secret`,
);

const HEX_64 = /^[0-9a-f]{64}$/;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** The derived organization registration principal (user key + user secret). */
export interface OrgProtocolRegistrationPrincipalV1 {
  /** Registration user key (64 lowercase hex chars). */
  readonly userKeyHex: string;
  /** Registration user secret (64 lowercase hex chars). */
  readonly userSecretKeyHex: string;
}

function assertFoundingKey(orgFoundingEpochKeyBytes: Uint8Array): void {
  if (orgFoundingEpochKeyBytes.length !== 32) {
    throw new OrgProtocolKeyError('founding-key-malformed');
  }
}

function assertOrgClientId(orgClientIdHex: string): void {
  if (!UUID_RE.test(orgClientIdHex)) {
    throw new OrgProtocolKeyError('org-client-id-malformed');
  }
}

function hkdf32(
  info: Uint8Array,
  orgFoundingEpochKeyBytes: Uint8Array,
  orgClientIdHex: string,
): Uint8Array {
  return hkdf(
    sha256,
    Uint8Array.from(orgFoundingEpochKeyBytes),
    utf8(orgClientIdHex.toLowerCase()),
    info,
    32,
  );
}

/**
 * Derive the organization protocol apiKey from the org-common group's
 * founding (epoch 1) key. Deterministic in (founding key, organization
 * client id): every authorized client derives the identical 64-hex key
 * from the same inputs, and the result satisfies the SDK credential
 * apiKey shape unchanged.
 */
export function deriveOrgProtocolApiKey(
  orgFoundingEpochKeyBytes: Uint8Array,
  orgClientIdHex: string,
): string {
  assertFoundingKey(orgFoundingEpochKeyBytes);
  assertOrgClientId(orgClientIdHex);
  const apiKey = bytesToHex(hkdf32(API_KEY_HKDF_INFO, orgFoundingEpochKeyBytes, orgClientIdHex));
  if (!HEX_64.test(apiKey)) {
    // Unreachable by construction; guards the derivation contract.
    throw new OrgProtocolKeyError('founding-key-malformed');
  }
  return apiKey;
}

/**
 * Derive the organization registration principal from the org-common
 * group's founding (epoch 1) key. The organization's admin row
 * bootstraps from this principal, and the admin then pre-registers every
 * wallet execution principal, so a shared wallet principal can never
 * land in the admin row. The auth hash over the registration principal
 * composes through the execution credential family's auth-hash rule with
 * the derived organization apiKey.
 */
export function deriveOrgProtocolRegistrationPrincipal(
  orgFoundingEpochKeyBytes: Uint8Array,
  orgClientIdHex: string,
): OrgProtocolRegistrationPrincipalV1 {
  assertFoundingKey(orgFoundingEpochKeyBytes);
  assertOrgClientId(orgClientIdHex);
  return {
    userKeyHex: bytesToHex(hkdf32(REGISTRATION_USER_KEY_HKDF_INFO, orgFoundingEpochKeyBytes, orgClientIdHex)),
    userSecretKeyHex: bytesToHex(
      hkdf32(REGISTRATION_USER_SECRET_HKDF_INFO, orgFoundingEpochKeyBytes, orgClientIdHex),
    ),
  };
}
