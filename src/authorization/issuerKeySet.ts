/**
 * The issuer key-set model: the published Ed25519 verification keys for
 * authorization artifacts, fetched byte-verbatim from
 * GET /api/v2/authorization/issuer-keyset?network=... and pinned by SHA-384
 * so a production enforcer knows exactly which key set it verified against.
 *
 * The doc the server serves is byte-stable (no timestamps, sorted keys), so
 * the hash a client pins today still matches after any refetch until the
 * server rotates. An enforcer SHOULD pin expectedSha384 in production;
 * fetching without a pin is a development convenience and is reported in
 * the loaded result.
 */

import { computeSHA384, constantTimeCompare } from '../wasm-loader';

export const ISSUER_KEYSET_DOC_VERSION = 1;
/** Retention window the server keeps retired keys published for. */
export const ISSUER_KEYSET_RETENTION_SECONDS = 172800;
/** The key-id prefix that scopes verification keys to this lane. */
export const ISSUER_KID_PREFIX = 'authz-ed25519-v1.';

export interface IssuerKeysetEntry {
  kid: string;
  /** The key's own network scope (pknetwork), distinct from the doc's. */
  pknetwork: string;
  /** 32-byte Ed25519 public key, hex. */
  publicKeyHex: string;
  status: 'active' | 'retired';
  supersededAt?: number;
}

export interface IssuerKeysetDoc {
  version: number;
  network: string;
  retentionSeconds: number;
  keys: IssuerKeysetEntry[];
}

export interface LoadedIssuerKeySet {
  doc: IssuerKeysetDoc;
  /** The SHA-384 hex of the exact bytes served. */
  sha384: string;
  /** The raw served bytes — the hash's preimage, kept for audit. */
  rawBytes: Uint8Array;
  /** True when the caller pinned (and the fetch matched) a SHA-384. */
  pinned: boolean;
}

export class IssuerKeySetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IssuerKeySetError';
    Object.setPrototypeOf(this, IssuerKeySetError.prototype);
  }
}

function fail(message: string): never {
  throw new IssuerKeySetError(message);
}

export interface LoadIssuerKeySetOptions {
  /** Server base URL (e.g. https://staging.sigbash.com). */
  serverUrl: string;
  network: string;
  /** SHA-384 hex pin; production enforcers set this. */
  expectedSha384?: string;
  fetchImpl?: typeof fetch;
}

// Per-network in-memory cache: the doc is byte-stable, so one fetch per
// network per process is sufficient; a caller may bypass it by pinning and
// catching the pin mismatch below.
const keySetCache = new Map<string, LoadedIssuerKeySet>();

function normalizeServerUrl(serverUrl: string): string {
  return serverUrl.replace(/\/+$/, '');
}

/** Validate the served doc's shape before any key is trusted. */
function parseIssuerKeysetDoc(rawBytes: Uint8Array, network: string): IssuerKeysetDoc {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(rawBytes));
  } catch {
    fail('issuer keyset is not valid JSON');
  }
  const doc = parsed as Record<string, unknown>;
  if (doc.version !== ISSUER_KEYSET_DOC_VERSION) {
    fail(`unsupported issuer keyset doc version ${String(doc.version)}`);
  }
  if (doc.network !== network) {
    fail(`issuer keyset network ${String(doc.network)} does not match the requested ${network}`);
  }
  if (doc.retention_seconds !== ISSUER_KEYSET_RETENTION_SECONDS) {
    fail(`issuer keyset retention ${String(doc.retention_seconds)} is outside the supported window`);
  }
  if (!Array.isArray(doc.keys) || doc.keys.length === 0) {
    fail('issuer keyset carries no keys');
  }
  const seen = new Set<string>();
  const keys = (doc.keys as Record<string, unknown>[]).map((entry) => {
    const kid = entry.kid;
    if (typeof kid !== 'string' || !kid.startsWith(ISSUER_KID_PREFIX)) {
      fail(`issuer key id '${String(kid)}' is outside the ${ISSUER_KID_PREFIX}* namespace`);
    }
    if (seen.has(kid)) fail(`issuer keyset carries duplicate kid ${kid}`);
    seen.add(kid);
    if (typeof entry.public_key_hex !== 'string' ||
        !/^[0-9a-f]{64}$/.test(entry.public_key_hex)) {
      fail(`issuer key ${kid} does not carry a 32-byte hex public key`);
    }
    if (entry.status !== 'active' && entry.status !== 'retired') {
      fail(`issuer key ${kid} carries unknown status ${String(entry.status)}`);
    }
    const supersededAt = entry.superseded_at;
    if (supersededAt !== undefined && typeof supersededAt !== 'number') {
      fail(`issuer key ${kid} carries a non-numeric superseded_at`);
    }
    const built: IssuerKeysetEntry = {
      kid,
      pknetwork: typeof entry.pknetwork === 'string' ? entry.pknetwork : '',
      publicKeyHex: entry.public_key_hex as string,
      status: entry.status as IssuerKeysetEntry['status'],
    };
    if (supersededAt !== undefined) built.supersededAt = supersededAt as number;
    return built;
  });
  const active = keys.filter(k => k.status === 'active');
  if (active.length === 0) {
    fail('issuer keyset carries no active key');
  }
  return {
    version: ISSUER_KEYSET_DOC_VERSION,
    network,
    retentionSeconds: doc.retention_seconds as number,
    keys,
  };
}

/**
 * Fetch and pin the issuer key set for one network. With expectedSha384 set,
 * a mismatch refuses the whole key set (fail closed). Without a pin the
 * result's `pinned` flag is false — the caller's detail surface must say so.
 */
export async function loadIssuerKeySet(options: LoadIssuerKeySetOptions): Promise<LoadedIssuerKeySet> {
  const { serverUrl, network, expectedSha384, fetchImpl = fetch } = options;
  const url = `${normalizeServerUrl(serverUrl)}/api/v2/authorization/issuer-keyset?network=${encodeURIComponent(network)}`;
  const response = await fetchImpl(url);
  if (!response.ok) {
    fail(`issuer keyset fetch failed with HTTP ${response.status}`);
  }
  const rawBytes = new Uint8Array(await response.arrayBuffer());
  const sha384 = await computeSHA384(rawBytes.buffer.slice(
    rawBytes.byteOffset, rawBytes.byteOffset + rawBytes.byteLength));
  if (expectedSha384 !== undefined && !constantTimeCompare(sha384, expectedSha384.toLowerCase())) {
    fail('issuer keyset bytes do not match the pinned SHA-384');
  }
  const doc = parseIssuerKeysetDoc(rawBytes, network);
  const loaded: LoadedIssuerKeySet = {
    doc, sha384, rawBytes, pinned: expectedSha384 !== undefined,
  };
  keySetCache.set(network, loaded);
  return loaded;
}

/** The process-cached key set for a network, if one has been loaded. */
export function cachedIssuerKeySet(network: string): LoadedIssuerKeySet | undefined {
  return keySetCache.get(network);
}

/** The active verification key for a kid from a loaded key set. */
export function issuerKeyForKid(
  keySet: LoadedIssuerKeySet, kid: string,
): IssuerKeysetEntry | undefined {
  return keySet.doc.keys.find(k => k.kid === kid && k.status === 'active');
}
