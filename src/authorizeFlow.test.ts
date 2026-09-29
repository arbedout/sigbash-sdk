/**
 * The authorizePSBT and getAuthorizationStatus client flows, mocked at the
 * two boundaries the flows own: the WASM export on globalThis and the
 * socket events. Proves the gate order (disposed → export presence →
 * lifetime → preflight → network cross-check), the honest-failure mapping,
 * the idempotent-replay tolerance, and the post-decode cross-checks.
 */

import { getPublicKey as ed25519Pubkey } from '@noble/ed25519';
import { SigbashClient } from './SigbashClient';
import { ClientDisposedError, ServerError, TOTPRequiredError } from './errors';
import {
  buildPsbtBytes,
  bytesToHex,
  honestEnvelopeJSON,
  honestSubjectCommitment,
  ISSUER_SEED,
  issue,
  wasmExportSuccess,
} from './__tests__/helpers/authorization-issuance';

const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');

jest.mock('./prove-worker-manager', () => ({
  getProveWorkerManager: () => ({
    init: async () => undefined,
    warmCircuits: () => undefined,
    getStatus: () => ({ ready: true, workerCount: 1 }),
    proveAsync: async () => { throw new Error('not exercised'); },
    witnessAndProveAsync: async () => { throw new Error('not exercised'); },
  }),
  ProveWorkerManager: class {},
}));

function stubClient(): SigbashClient {
  return new SigbashClient({
    serverUrl: 'https://unit.test',
    apiKey: 'a'.repeat(64),
    userKey: 'b'.repeat(64),
    userSecretKey: 'c'.repeat(40),
  });
}

type RequestCapture = { event: string; payload: Record<string, unknown> };

function stubSocket(handler: (event: string, payload: Record<string, unknown>) => unknown) {
  const requests: RequestCapture[] = [];
  const socket = {
    requests,
    async request(event: string, payload: Record<string, unknown>) {
      requests.push({ event, payload });
      return handler(event, payload);
    },
  };
  jest.spyOn(SigbashClient.prototype as unknown as Record<string, unknown>, '_requireSocket')
    .mockImplementation(() => socket);
  jest.spyOn(SigbashClient.prototype as unknown as Record<string, unknown>, '_prefetchCovenantState')
    .mockImplementation(async () => undefined);
  return socket;
}

function stubAuthHash(client: SigbashClient): void {
  (client as unknown as Record<string, unknown>)['_authHash'] = Promise.resolve('ff'.repeat(32));
}

function stubWasm(result: Record<string, unknown> | ((...args: unknown[]) => Promise<never>)): jest.Mock {
  const stub = typeof result === 'function'
    ? jest.fn(result)
    : jest.fn(async () => result);
  (globalThis as unknown as Record<string, unknown>)['SigbashWASM_AuthorizePSBT'] = stub;
  return stub;
}

const BASE_OPTIONS = {
  keyId: '7',
  psbtBase64: toBase64(buildPsbtBytes()),
  kmcJSON: '{"key_index":0}',
  network: 'signet' as const,
};

describe('authorizePSBT client flow (mocked boundaries)', () => {
  const originalWasm = (globalThis as unknown as Record<string, unknown>)['SigbashWASM_AuthorizePSBT'];

  afterEach(() => {
    jest.restoreAllMocks();
    if (originalWasm === undefined) {
      delete (globalThis as unknown as Record<string, unknown>)['SigbashWASM_AuthorizePSBT'];
    } else {
      (globalThis as unknown as Record<string, unknown>)['SigbashWASM_AuthorizePSBT'] = originalWasm;
    }
  });

  it('runs preflight before the export, then issues, and returns the result', async () => {
    const client = stubClient();
    const issuance = issue();
    const socket = stubSocket((event) => {
      if (event === 'authorize_preflight') return { success: true, network: 'signet' };
      if (event === 'authorize_issue') {
        return {
          success: true,
          artifact: toBase64(issuance.rawArtifact),
          artifact_signature: toBase64(issuance.rawSignature),
        };
      }
      throw new Error(`unexpected event ${event}`);
    });
    stubAuthHash(client);
    const wasmStub = stubWasm(wasmExportSuccess(honestEnvelopeJSON()));

    const result = await client.authorizePSBT(BASE_OPTIONS);

    // Gate order: preflight is captured before the export runs.
    expect(socket.requests.map(r => r.event)).toEqual(['authorize_preflight', 'authorize_issue']);
    expect(wasmStub).toHaveBeenCalled();
    expect(socket.requests[0].payload).toMatchObject({
      key_id: '7',
      totp_code: null,
      access_generation: null,
    });
    expect(socket.requests[1].payload).toMatchObject({
      key_id: '7',
      subject_commitment_hex: bytesToHex(honestSubjectCommitment()),
      lifetime_seconds: 900,
    });
    // The artifact and the envelope ride the result; the action key is
    // derived from the echoed burn pair.
    expect(result.artifact.issuerKid).toBe(issuance.fields.issuerKid);
    expect(result.envelopeJson).toBe(honestEnvelopeJSON());
    expect(result.burnCommitments).toHaveLength(2);
    expect(result.actionKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(result.sessionIdHex).toMatch(/^[0-9a-f]{64}$/);
    expect(result.pathId).toMatch(/^[0-9a-f]{64}$/);
  });

  it('tolerates the idempotent-replay issuance shape (artifact only, replayed flag)', async () => {
    const client = stubClient();
    const issuance = issue();
    const socket = stubSocket((event) => {
      if (event === 'authorize_preflight') return { success: true, network: 'signet' };
      if (event === 'authorize_issue') {
        return {
          success: true,
          replayed: true,
          artifact: toBase64(issuance.rawArtifact),
          artifact_signature: toBase64(issuance.rawSignature),
        };
      }
      throw new Error(`unexpected event ${event}`);
    });
    stubAuthHash(client);
    stubWasm(wasmExportSuccess(honestEnvelopeJSON()));

    const result = await client.authorizePSBT(BASE_OPTIONS);
    expect(result.artifact.subjectCommitment).toEqual(issuance.fields.subjectCommitment);
    // No server action_key on the replay shape — derived from the burn pair.
    expect(result.actionKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  it('maps the honest WASM failures to their stable codes', async () => {
    const client = stubClient();
    stubSocket(() => ({ success: true, network: 'signet' }));
    stubAuthHash(client);

    stubWasm({ success: false, reason: 'POLICY_NOT_SATISFIED', detail: 'clause 2' });
    await expect(client.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({ code: 'POLICY_REJECTED' });

    stubWasm({ success: false, reason: 'INVALID_LIFETIME', detail: 'lifetime out of range' });
    await expect(client.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({ code: 'INVALID_LIFETIME' });

    stubWasm({ success: false, reason: 'AUTHZ_SESSION_SHAPE_REJECTED', detail: 'multi-position session' });
    await expect(client.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({
      code: 'AUTHZ_SESSION_SHAPE_REJECTED',
    });

    // The thrown-error path maps the same reasons.
    stubWasm(async () => { throw { error: 'POLICY_NOT_SATISFIED' }; });
    await expect(client.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({ code: 'POLICY_REJECTED' });
  });

  it('refuses before preflight when the export is absent or the lifetime is out of range', async () => {
    const client = stubClient();
    const socket = stubSocket(() => { throw new Error('must not be reached'); });
    stubAuthHash(client);

    // The dispose gate is the very first check.
    client.dispose();
    await expect(client.authorizePSBT(BASE_OPTIONS)).rejects.toBeInstanceOf(ClientDisposedError);

    const freshClient = stubClient();
    stubSocket(() => { throw new Error('must not be reached'); });
    stubAuthHash(freshClient);
    await expect(freshClient.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({ code: 'WASM_NOT_LOADED' });

    stubWasm({ success: true });
    await expect(freshClient.authorizePSBT({ ...BASE_OPTIONS, lifetimeSeconds: 0 }))
      .rejects.toMatchObject({ code: 'INVALID_LIFETIME' });
    await expect(freshClient.authorizePSBT({ ...BASE_OPTIONS, lifetimeSeconds: 86401 }))
      .rejects.toMatchObject({ code: 'INVALID_LIFETIME' });
    expect(socket.requests).toHaveLength(0);
  });

  it('maps the preflight gates: TOTP required, capability not enabled, network mismatch', async () => {
    const client = stubClient();
    stubSocket(() => {
      throw new ServerError('totp', 400, { code: 'TOTP_REQUIRED' });
    });
    stubAuthHash(client);
    stubWasm({ success: true });
    await expect(client.authorizePSBT(BASE_OPTIONS)).rejects.toBeInstanceOf(TOTPRequiredError);

    const gatedClient = stubClient();
    stubSocket(() => {
      throw new ServerError('gate', 403, { code: 'CAPABILITY_NOT_ENABLED' });
    });
    stubAuthHash(gatedClient);
    await expect(gatedClient.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({
      code: 'CAPABILITY_NOT_ENABLED',
    });

    const echoClient = stubClient();
    stubSocket(() => ({ success: true, network: 'mainnet' }));
    stubAuthHash(echoClient);
    await expect(echoClient.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({
      code: 'NETWORK_MISMATCH',
    });
  });

  it('maps the shared burn-state race to AUTHORIZATION_ALREADY_CONSUMED', async () => {
    const client = stubClient();
    stubSocket((event) => {
      if (event === 'authorize_preflight') return { success: true, network: 'signet' };
      throw new ServerError('consumed', 409, { code: 'AUTHORIZATION_ALREADY_CONSUMED' });
    });
    stubAuthHash(client);
    stubWasm(wasmExportSuccess(honestEnvelopeJSON()));
    await expect(client.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({
      code: 'AUTHORIZATION_ALREADY_CONSUMED',
    });
  });

  it('refuses an export whose subject commitment disagrees with the artifact', async () => {
    const client = stubClient();
    const issuance = issue();
    stubSocket((event) => {
      if (event === 'authorize_preflight') return { success: true, network: 'signet' };
      return {
        success: true,
        artifact: toBase64(issuance.rawArtifact),
        artifact_signature: toBase64(issuance.rawSignature),
      };
    });
    stubAuthHash(client);
    const forged = { ...wasmExportSuccess(honestEnvelopeJSON()), subject_commitment_hex: 'ab'.repeat(32) };
    stubWasm(forged);
    await expect(client.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({
      code: 'SUBJECT_MISMATCH',
    });
  });

  it('refuses a forged artifact signature at issuance when the key set is cached', async () => {
    const client = stubClient();
    const issuance = issue();
    // Corrupt the signature the server "returned".
    const badSignature = Uint8Array.from(issuance.rawSignature);
    badSignature[0] ^= 0x01;
    stubSocket((event) => {
      if (event === 'authorize_preflight') return { success: true, network: 'signet' };
      return {
        success: true,
        artifact: toBase64(issuance.rawArtifact),
        artifact_signature: toBase64(badSignature),
      };
    });
    stubAuthHash(client);
    // Pre-seed the per-network cache so the signature check runs client-side.
    const { loadIssuerKeySet } = await import('./authorization/issuerKeySet');
    await loadIssuerKeySet({
      serverUrl: 'https://unit.test',
      network: 'signet',
      fetchImpl: (async () => new Response(JSON.stringify({
        version: 1,
        network: 'signet',
        retention_seconds: 172800,
        keys: [{
          kid: issuance.fields.issuerKid,
          pknetwork: 'signet',
          public_key_hex: bytesToHex(ed25519Pubkey(ISSUER_SEED)),
          status: 'active',
        }],
      }), { status: 200 })) as unknown as typeof fetch,
    });
    stubWasm(wasmExportSuccess(honestEnvelopeJSON()));
    await expect(client.authorizePSBT(BASE_OPTIONS)).rejects.toMatchObject({
      code: 'AUTHORIZATION_BAD_SIGNATURE',
    });
  });
});

describe('getAuthorizationStatus (mocked socket)', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('resolves the action key from each accepted input and reports the server status', async () => {
    const { authorizationActionKeyFromBurnPair } = await import('./authorization/adapterRegistry');
    const burnPair: [string, string] = ['11'.repeat(32), '22'.repeat(32)];
    const derivedKey = bytesToHex(authorizationActionKeyFromBurnPair(burnPair));

    const cases: Array<[Record<string, unknown>, string]> = [
      [{ actionKey: 'aa'.repeat(32) }, 'aa'.repeat(32)],
      [{ burnCommitments: burnPair }, derivedKey],
      [{
        authorization: {
          burnCommitments: burnPair,
          actionKeyHex: 'bb'.repeat(32),
        },
      }, 'bb'.repeat(32)],
    ];
    for (const [options, expectedKey] of cases) {
      const client = stubClient();
      const socket = stubSocket(() => ({
        success: true,
        status: 'burned',
        issuer_kid: 'authz-ed25519-v1.1',
        issued_at: 1790000000,
        expires_at: 1790000900,
      }));
      stubAuthHash(client);
      const result = await client.getAuthorizationStatus(options as never);
      expect(result.status).toBe('burned');
      expect(result.actionKeyHex).toBe(expectedKey);
      expect(result.issuerKid).toBe('authz-ed25519-v1.1');
      expect(socket.requests[0].event).toBe('authorization_status');
      expect(socket.requests[0].payload).toMatchObject({ action_key: expectedKey });
    }

    const notFoundClient = stubClient();
    stubSocket(() => ({ success: true, status: 'not_found' }));
    stubAuthHash(notFoundClient);
    const result = await notFoundClient.getAuthorizationStatus({ actionKey: 'cc'.repeat(32) });
    expect(result.status).toBe('not_found');
  });

  it('refuses with MISSING_FIELD when no action-key input exists', async () => {
    const client = stubClient();
    stubSocket(() => { throw new Error('unreachable'); });
    stubAuthHash(client);
    await expect(client.getAuthorizationStatus({} as never)).rejects.toMatchObject({
      code: 'MISSING_FIELD',
    });
  });

  it('never treats an unknown server status as burned', async () => {
    const client = stubClient();
    stubSocket(() => ({ success: true, status: 'weird-state' }));
    stubAuthHash(client);
    const result = await client.getAuthorizationStatus({ actionKey: 'dd'.repeat(32) });
    expect(result.status).toBe('not_found');
  });
});
