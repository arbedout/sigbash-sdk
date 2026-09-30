/**
 * The key model's orthogonal dimensions (ADR-033 §9) as additive KMC
 * container metadata: who generated the key material (origin), its
 * cryptographic algorithm (scheme), and what the key may do (capabilities).
 *
 * Three invariants:
 *  - Legacy containers deserialize unchanged in BEHAVIOR: every absent field
 *    gets an explicit default, never a reinterpretation of what is present.
 *  - The fields never enter identity digests or subject commitments — they
 *    are provenance and capability decoration, not key identity (the
 *    provisioning precedent: the fingerprint commits the origin-less
 *    canonical text).
 *  - No KMC version bump: the fields are additive metadata, byte-transparent
 *    on rewrap.
 */

export const KEY_ORIGIN_DEFAULT: KeyOrigin = 'sigbash';
export const KEY_SCHEME_DEFAULT: KeyScheme = 'secp256k1_schnorr';
export const KEY_CAPABILITIES_DEFAULT: KeyCapability[] = ['bitcoin_sign'];

/** Who generated / controls the key material. */
export type KeyOrigin = 'sigbash' | 'user_provided';

/** Cryptographic algorithm of the key material — not a chain identity.
 * The identifier schemes mark authorization-only identities: a
 * descriptor-derived key or a client-chosen identifier whose container
 * carries no MuSig2 aggregate material and registers without client-key
 * commitment fields. */
export type KeyScheme =
  | 'secp256k1_schnorr'
  | 'descriptor_derived'
  | 'client_chosen_identifier';

/** Structured capabilities a key advertises. */
export type KeyCapability = 'bitcoin_sign' | 'transaction_authorize';

export interface KeyModelMetadata {
  origin: KeyOrigin;
  scheme: KeyScheme;
  capabilities: KeyCapability[];
}

const KNOWN_ORIGINS: readonly KeyOrigin[] = ['sigbash', 'user_provided'];
export const KNOWN_KEY_SCHEMES: readonly KeyScheme[] = [
  'secp256k1_schnorr',
  'descriptor_derived',
  'client_chosen_identifier',
];
const KNOWN_SCHEMES = KNOWN_KEY_SCHEMES;
const KNOWN_CAPABILITIES: readonly KeyCapability[] = ['bitcoin_sign', 'transaction_authorize'];

/** The identifier schemes — authorization-only identity forms whose
 * containers carry no MuSig2 aggregate material. */
const IDENTIFIER_SCHEMES: readonly KeyScheme[] = ['descriptor_derived', 'client_chosen_identifier'];

/** Whether a normalized key-model declaration describes an
 * authorization-only identity: an identifier scheme carrying exactly the
 * transaction-authorize capability. */
export function isIdentifierKeyScheme(scheme: KeyScheme): boolean {
  return IDENTIFIER_SCHEMES.includes(scheme);
}

/** Whether a key can sign: the signing capability is present on a
 * signing-scheme declaration, or the key carries no declaration at all
 * (the legacy posture, whose containers are signing-shaped by
 * construction). An identifier scheme is never signing-capable. */
export function keyCanSign(metadata: KeyModelMetadata): boolean {
  if (isIdentifierKeyScheme(metadata.scheme)) return false;
  return metadata.capabilities.includes('bitcoin_sign');
}

function rejectUnknown(field: string, value: unknown, known: readonly string[]): never {
  throw new Error(`${field} '${String(value)}' is outside the known set {${known.join(', ')}}`);
}

/**
 * Normalize a freshly-decrypted KMC's key-model metadata in place: present
 * fields are validated (an unknown value is a container corruption, not a
 * silent default), absent fields get the legacy defaults. Returns the same
 * object for chaining.
 */
export function normalizeKeyModelMetadata(kmc: object): object {
  const container = kmc as Record<string, unknown>;
  const origin = container.origin;
  if (origin === undefined) {
    container.origin = KEY_ORIGIN_DEFAULT;
  } else if (!KNOWN_ORIGINS.includes(origin as KeyOrigin)) {
    rejectUnknown('origin', origin, KNOWN_ORIGINS);
  }
  const scheme = container.scheme;
  if (scheme === undefined) {
    container.scheme = KEY_SCHEME_DEFAULT;
  } else if (!KNOWN_SCHEMES.includes(scheme as KeyScheme)) {
    rejectUnknown('scheme', scheme, KNOWN_SCHEMES);
  }
  const capabilities = container.capabilities;
  if (capabilities === undefined) {
    container.capabilities = [...KEY_CAPABILITIES_DEFAULT];
  } else {
    if (!Array.isArray(capabilities) ||
        capabilities.some(c => !KNOWN_CAPABILITIES.includes(c as KeyCapability))) {
      rejectUnknown('capabilities', Array.isArray(capabilities) ? capabilities.join(',') : capabilities,
        KNOWN_CAPABILITIES);
    }
    if (new Set(capabilities).size !== capabilities.length) {
      throw new Error('capabilities carries a duplicate entry');
    }
  }
  return kmc;
}

/**
 * Stamp the key-model metadata onto a KMC before a rewrap. Present values
 * win (a BYO-key container keeps its declared origin); only absent fields
 * are defaulted, so rewrapping is byte-transparent for anything the
 * container already declares.
 */
export function stampKeyModelMetadata(kmc: object): object {
  return normalizeKeyModelMetadata(kmc);
}

/** The display role a key plays, for listing surfaces. Capabilities decide:
 * a key that authorizes and signs is both, one that only authorizes is
 * authorization-only, and the signing default stays 'signing'. Origin breaks
 * ties only when a container carries no capability at all (a user-provided
 * key with no declared capabilities is authorization-capable; a
 * Sigbash-generated one is the signing key). */
export type AuthorizationKeyRole =
  | 'signing'
  | 'authorization_only'
  | 'signing_and_authorization';

export function authorizationKeyRoleOf(metadata: KeyModelMetadata): AuthorizationKeyRole {
  const signs = metadata.capabilities.includes('bitcoin_sign');
  const authorizes = metadata.capabilities.includes('transaction_authorize');
  if (signs && authorizes) return 'signing_and_authorization';
  if (authorizes) return 'authorization_only';
  if (signs) return 'signing';
  return metadata.origin === 'user_provided' ? 'authorization_only' : 'signing';
}

/** The normalized view of a container's key-model metadata (read-only). */
export function keyModelMetadataOf(kmc: object): KeyModelMetadata {
  const normalized = normalizeKeyModelMetadata({ ...kmc });
  const container = normalized as Record<string, unknown>;
  return {
    origin: container.origin as KeyOrigin,
    scheme: container.scheme as KeyScheme,
    capabilities: container.capabilities as KeyCapability[],
  };
}
