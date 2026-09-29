/**
 * The issuer key-set surface: shape validation fails closed on every
 * malformed field, the SHA-384 pin is enforced with a constant-time
 * compare, and the per-network cache holds byte-stable documents.
 */

import { createHash } from 'crypto';
import {
  ISSUER_KEYSET_DOC_VERSION,
  ISSUER_KEYSET_RETENTION_SECONDS,
  IssuerKeySetError,
  cachedIssuerKeySet,
  loadIssuerKeySet,
} from './issuerKeySet';

const ACTIVE_KEY = {
  kid: 'authz-ed25519-v1.1',
  pknetwork: 'signet',
  public_key_hex: 'aa'.repeat(32),
  status: 'active',
};
const RETIRED_KEY = {
  kid: 'authz-ed25519-v1.0',
  pknetwork: 'signet',
  public_key_hex: 'bb'.repeat(32),
  status: 'retired',
  superseded_at: 1790000000,
};

function docBytes(doc: object): Uint8Array {
  return Uint8Array.from(Buffer.from(JSON.stringify(doc), 'utf8'));
}

function goodDoc(): object {
  return {
    version: ISSUER_KEYSET_DOC_VERSION,
    network: 'signet',
    retention_seconds: ISSUER_KEYSET_RETENTION_SECONDS,
    keys: [RETIRED_KEY, ACTIVE_KEY],
  };
}

function fetchReturning(bytes: Uint8Array): typeof fetch {
  return (async () => new Response(Buffer.from(bytes), { status: 200 })) as unknown as typeof fetch;
}

describe('issuer key set', () => {
  it('loads, hashes, and caches a well-formed document', async () => {
    const bytes = docBytes(goodDoc());
    const loaded = await loadIssuerKeySet({
      serverUrl: 'https://issuer.test/',
      network: 'signet',
      fetchImpl: fetchReturning(bytes),
    });
    expect(loaded.pinned).toBe(false);
    expect(loaded.sha384).toBe(createHash('sha384').update(Buffer.from(bytes)).digest('hex'));
    expect(loaded.doc.keys).toHaveLength(2);
    expect(cachedIssuerKeySet('signet')).toBe(loaded);
  });

  it('refuses a pinned hash mismatch and honors a matching pin', async () => {
    const bytes = docBytes(goodDoc());
    const sha384 = createHash('sha384').update(Buffer.from(bytes)).digest('hex');
    await expect(loadIssuerKeySet({
      serverUrl: 'https://issuer.test', network: 'signet',
      expectedSha384: sha384, fetchImpl: fetchReturning(bytes),
    })).resolves.toMatchObject({ pinned: true });

    await expect(loadIssuerKeySet({
      serverUrl: 'https://issuer.test', network: 'signet',
      expectedSha384: 'e'.repeat(96), fetchImpl: fetchReturning(bytes),
    })).rejects.toThrow(IssuerKeySetError);
  });

  it('refuses HTTP failures', async () => {
    const failing = (async () => new Response('nope', { status: 503 })) as unknown as typeof fetch;
    await expect(loadIssuerKeySet({
      serverUrl: 'https://issuer.test', network: 'signet', fetchImpl: failing,
    })).rejects.toThrow(/503/);
  });

  const malformed: Array<[string, object]> = [
    ['wrong doc version', { ...goodDoc(), version: 2 }],
    ['wrong network', { ...goodDoc(), network: 'mainnet' }],
    ['wrong retention', { ...goodDoc(), retention_seconds: 60 }],
    ['no keys', { ...goodDoc(), keys: [] }],
    ['bad kid prefix', { ...goodDoc(), keys: [{ ...ACTIVE_KEY, kid: 'other.1' }] }],
    ['duplicate kid', { ...goodDoc(), keys: [ACTIVE_KEY, ACTIVE_KEY] }],
    ['short public key', { ...goodDoc(), keys: [{ ...ACTIVE_KEY, public_key_hex: 'aa'.repeat(31) }] }],
    ['non-hex public key', { ...goodDoc(), keys: [{ ...ACTIVE_KEY, public_key_hex: 'z'.repeat(64) }] }],
    ['unknown status', { ...goodDoc(), keys: [{ ...ACTIVE_KEY, status: 'pending' }] }],
    ['no active key', { ...goodDoc(), keys: [{ ...RETIRED_KEY }] }],
    ['non-numeric superseded_at', { ...goodDoc(), keys: [{ ...RETIRED_KEY, superseded_at: 'soon' }] }],
  ];
  for (const [label, doc] of malformed) {
    it(`refuses ${label}`, async () => {
      await expect(loadIssuerKeySet({
        serverUrl: 'https://issuer.test', network: 'signet',
        fetchImpl: fetchReturning(docBytes(doc)),
      })).rejects.toThrow(IssuerKeySetError);
    });
  }

  it('refuses a non-JSON body', async () => {
    await expect(loadIssuerKeySet({
      serverUrl: 'https://issuer.test', network: 'signet',
      fetchImpl: fetchReturning(Uint8Array.from(Buffer.from('<html>'))),
    })).rejects.toThrow(/JSON/);
  });
});
