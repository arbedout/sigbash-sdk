/**
 * Principal access lifecycle suite: ceremony orchestration (grant, revoke,
 * recovery rebind), transport-capture privacy invariants, typed error
 * mapping, and the WASM seam contract.
 *
 * The wasm seam is a faithful-shaped orchestration stub: it asserts the
 * exact request fields each ceremony receives and returns a well-formed
 * envelope. Ceremony correctness inside the binary is covered by the
 * envelope ceremonies' native tests — these tests never claim it.
 *
 * The transport-capture class is the privacy invariant: every method's
 * full request run is captured, and no body or delivery payload ever
 * contains the credential secret, the slot private key, or any non-opaque
 * wallet material.
 */

import {
  PrincipalAccessApi,
  defaultPrincipalAccessWasm,
  type PrincipalAccessWasm,
} from './principalAccess';
import { derivePrincipalSlotKey, parsePrincipalCredential } from './wallet/principalCredential';
import { AdminError, SigbashSDKError, WasmError } from './errors';

const ORG_API_KEY = '11'.repeat(32);
const KEY_ID = '7';
const GRANTOR = {
  selectedAuthMode: 'api',
  credentialId: 'api-1700000000-m/86h/1h/0h/0/0',
  authSecret: 'grantor-slot-secret',
};
const ENVELOPE = JSON.stringify({ envelope_id: 'env-1', auth_slots: [] });
const UPLOADED_ENVELOPE = JSON.stringify({ envelope_id: 'env-1', auth_slots: ['new-slot'] });
const REWRAPPED_ENVELOPE = JSON.stringify({ envelope_id: 'env-1', auth_slots: ['surviving'] });

interface RecordedCall {
  method: string;
  input: string;
  body?: string;
}

type RouteHandler = (call: RecordedCall) => { status: number; payload: unknown };

class CapturingTransport {
  readonly calls: RecordedCall[] = [];

  constructor(private readonly _handler: RouteHandler) {}

  async authedFetch(
    input: string,
    init?: RequestInit & { body?: string | Uint8Array | undefined },
  ): Promise<Response> {
    const call: RecordedCall = {
      method: (init?.method ?? 'GET').toUpperCase(),
      input,
      body: typeof init?.body === 'string' ? init.body : undefined,
    };
    this.calls.push(call);
    const out = this._handler(call);
    return {
      ok: out.status >= 200 && out.status < 300,
      status: out.status,
      json: async () => out.payload,
    } as unknown as Response;
  }

  /** All bodies ever sent, joined — the privacy-invariant scan surface. */
  bodies(): string {
    return this.calls.map(call => call.body ?? '').join('\n');
  }

  callsTo(method: string, pattern: RegExp): RecordedCall[] {
    return this.calls.filter(call => call.method === method && pattern.test(call.input));
  }
}

interface WasmRecord {
  ceremony: 'add' | 'rewrap';
  request: Record<string, unknown>;
  /** Transport-call count when the ceremony ran, for cross-seam ordering. */
  atCall: number;
}

function stubWasm(records: WasmRecord[], transport?: CapturingTransport): PrincipalAccessWasm {
  return {
    async addPrincipalSlot(request) {
      records.push({ ceremony: 'add', request: { ...request }, atCall: transport?.calls.length ?? 0 });
      return UPLOADED_ENVELOPE;
    },
    async rewrapEnvelope(request) {
      records.push({ ceremony: 'rewrap', request: { ...request }, atCall: transport?.calls.length ?? 0 });
      return REWRAPPED_ENVELOPE;
    },
  };
}

/**
 * Happy-path server: registration, access rows, and rewrap uploads all
 * succeed; the generation advances with each row change.
 */
function happyServer(): RouteHandler {
  let generation = 2;
  return call => {
    if (call.method === 'POST' && call.input === '/api/v2/sdk/admin/users') {
      return { status: 200, payload: { success: true } };
    }
    if (call.method === 'POST' && new RegExp(`/api/v2/sdk/keys/${KEY_ID}/access$`).test(call.input)) {
      generation += 1;
      const body = JSON.parse(call.body ?? '{}');
      return {
        status: 200,
        payload: {
          policy_key_id: KEY_ID,
          principal_auth_hash: body.principal_auth_hash,
          status: 'active',
          access_generation: generation,
        },
      };
    }
    if (call.method === 'DELETE' && new RegExp(`/api/v2/sdk/keys/${KEY_ID}/access/[0-9a-f]{64}$`).test(call.input)) {
      generation += 1;
      const hash = call.input.split('/').pop() as string;
      return {
        status: 200,
        payload: {
          policy_key_id: KEY_ID,
          principal_auth_hash: hash,
          status: 'revoked',
          access_generation: generation,
        },
      };
    }
    if (call.method === 'GET' && new RegExp(`/api/v2/sdk/keys/${KEY_ID}/access/[0-9a-f]{64}$`).test(call.input)) {
      const hash = call.input.split('/').pop() as string;
      return {
        status: 200,
        payload: {
          policy_key_id: KEY_ID,
          principal_auth_hash: hash,
          status: 'active',
          access_generation: generation,
        },
      };
    }
    if (call.method === 'GET' && call.input === `/api/v2/sdk/keys/${KEY_ID}/access`) {
      return { status: 200, payload: [] };
    }
    if (call.method === 'POST' && call.input === `/api/v2/sdk/keys/${KEY_ID}/kmc/rewrap`) {
      return { status: 200, payload: { success: true, key_id: KEY_ID, access_generation: generation } };
    }
    return { status: 404, payload: { error: true, code: 'NOT_FOUND', message: 'Key not found' } };
  };
}

function makeApi(handler: RouteHandler = happyServer()) {
  const transport = new CapturingTransport(handler);
  const wasmRecords: WasmRecord[] = [];
  const api = new PrincipalAccessApi(
    transport as never,
    ORG_API_KEY,
    stubWasm(wasmRecords, transport),
  );
  return { api, transport, wasmRecords };
}

/** Every secret fragment of a ceremony run — none of these may reach a body. */
function secretFragments(result: { credential: { userSecretKey: string } }): string[] {
  return [
    result.credential.userSecretKey,
    derivePrincipalSlotKey(ORG_API_KEY, result.credential.userSecretKey).privateKeyHex,
  ];
}

describe('grant ceremony', () => {
  it('composes registration, slot add, access row, and envelope upload in order', async () => {
    const { api, transport, wasmRecords } = makeApi();
    const result = await api.grant({
      policyKeyId: KEY_ID,
      envelopeJson: ENVELOPE,
      grantor: GRANTOR,
      observedAccessGeneration: 2,
      clientKeyCommitmentH1: 'h1'.repeat(32),
      clientKeyHash: 'kh'.repeat(32),
    });

    const register = transport.callsTo('POST', /\/admin\/users$/);
    const adds = wasmRecords.filter(record => record.ceremony === 'add');
    const grants = transport.callsTo('POST', /\/access$/);
    const uploads = transport.callsTo('POST', /\/kmc\/rewrap$/);
    expect(register).toHaveLength(1);
    expect(adds).toHaveLength(1);
    expect(grants).toHaveLength(1);
    expect(uploads).toHaveLength(1);

    // Order: registration, then slot add, then the access row, then the
    // replacement envelope upload.
    expect(adds[0].atCall).toBeGreaterThan(transport.calls.indexOf(register[0]));
    expect(transport.calls.indexOf(grants[0])).toBe(adds[0].atCall);
    expect(transport.calls.indexOf(grants[0])).toBeLessThan(transport.calls.indexOf(uploads[0]));

    expect(register[0].body).toContain(result.authHash);
    expect(JSON.parse(register[0].body as string).new_user_pop_pubkey).toMatch(/^[0-9a-f]{64}$/);

    // The slot-add ceremony receives the grantor slot and the principal's
    // slot public key, addressed by the credential user key.
    expect(adds[0].request).toMatchObject({
      envelopeJson: ENVELOPE,
      selectedAuthMode: GRANTOR.selectedAuthMode,
      credentialId: GRANTOR.credentialId,
      authSecret: GRANTOR.authSecret,
      newCredentialId: result.credential.userKey,
    });
    expect(adds[0].request.principalPublicKeyHex).toMatch(/^0[23][0-9a-f]{64}$/);

    expect(JSON.parse(grants[0].body as string)).toEqual({
      principal_auth_hash: result.authHash,
      access_generation: 2,
    });

    const uploadBody = JSON.parse(uploads[0].body as string);
    expect(uploadBody.encrypted_kmc).toBe(UPLOADED_ENVELOPE);
    expect(uploadBody.client_key_commitment_h1).toBe('h1'.repeat(32));
    expect(uploadBody.client_key_hash).toBe('kh'.repeat(32));
    expect(result.accessGeneration).toBe(3);
    expect(result.status.status).toBe('active');
    expect(result.slotCredentialId).toBe(result.credential.userKey);
  });

  it('round-trips the delivery payload back to the provisioned credential', async () => {
    const { api } = makeApi();
    const result = await api.grant({ policyKeyId: KEY_ID, envelopeJson: ENVELOPE, grantor: GRANTOR });
    expect(parsePrincipalCredential(result.delivery)).toEqual(result.credential);
  });

  it('skips registration when the caller provisions the PoP row themselves', async () => {
    const { api, transport } = makeApi();
    await api.grant({
      policyKeyId: KEY_ID,
      envelopeJson: ENVELOPE,
      grantor: GRANTOR,
      register: false,
    });
    expect(transport.callsTo('POST', /\/admin\/users$/)).toHaveLength(0);
  });

  it('never sends secret material, slot keys, or the delivery payload in any request', async () => {
    const { api, transport } = makeApi();
    const result = await api.grant({ policyKeyId: KEY_ID, envelopeJson: ENVELOPE, grantor: GRANTOR });
    const sent = transport.bodies();
    for (const secret of secretFragments(result)) {
      expect(sent).not.toContain(secret);
    }
    expect(sent).not.toContain('SIGPRINC');
    expect(sent).toContain(result.authHash);
  });

  it('omits the generation guard when no observation was supplied', async () => {
    const { api, transport } = makeApi();
    await api.grant({ policyKeyId: KEY_ID, envelopeJson: ENVELOPE, grantor: GRANTOR });
    const grantBody = JSON.parse(transport.callsTo('POST', /\/access$/)[0].body as string);
    expect(grantBody).not.toHaveProperty('access_generation');
  });

  it('surfaces a wasm ceremony failure as a wasm error', async () => {
    const brokenWasm: PrincipalAccessWasm = {
      addPrincipalSlot: async () => {
        throw new WasmError('principal slot add failed: boom');
      },
      rewrapEnvelope: async () => REWRAPPED_ENVELOPE,
    };
    const transport = new CapturingTransport(happyServer());
    const api = new PrincipalAccessApi(transport as never, ORG_API_KEY, brokenWasm);
    await expect(
      api.grant({ policyKeyId: KEY_ID, envelopeJson: ENVELOPE, grantor: GRANTOR }),
    ).rejects.toThrow(WasmError);
    // Nothing reached the network before the ceremony failed.
    expect(transport.calls.filter(call => /\/access$/.test(call.input))).toHaveLength(0);
  });
});

describe('revoke ceremony', () => {
  const PRINCIPAL_AUTH_HASH = 'd'.repeat(64);
  const SLOT_CREDENTIAL_ID = 'e'.repeat(32) + 'f'.repeat(32);

  it('reads status, flips the row, re-wraps the named slot away, and uploads', async () => {
    const { api, transport, wasmRecords } = makeApi();
    const result = await api.revoke({
      policyKeyId: KEY_ID,
      principalAuthHash: PRINCIPAL_AUTH_HASH,
      slotCredentialId: SLOT_CREDENTIAL_ID,
      envelopeJson: UPLOADED_ENVELOPE,
      grantor: GRANTOR,
      clientKeyCommitmentH1: 'h1'.repeat(32),
      clientKeyHash: 'kh'.repeat(32),
    });

    expect(transport.callsTo('GET', new RegExp(`/access/${PRINCIPAL_AUTH_HASH}$`))).toHaveLength(1);
    expect(transport.callsTo('DELETE', new RegExp(`/access/${PRINCIPAL_AUTH_HASH}$`))).toHaveLength(1);

    const rewraps = wasmRecords.filter(record => record.ceremony === 'rewrap');
    expect(rewraps).toHaveLength(1);
    expect(rewraps[0].request).toMatchObject({
      envelopeJson: UPLOADED_ENVELOPE,
      selectedAuthMode: GRANTOR.selectedAuthMode,
      credentialId: GRANTOR.credentialId,
      authSecret: GRANTOR.authSecret,
    });
    expect(rewraps[0].request.removeCredentialIds).toEqual([SLOT_CREDENTIAL_ID]);

    const uploadBody = JSON.parse(transport.callsTo('POST', /\/kmc\/rewrap$/)[0].body as string);
    expect(uploadBody.encrypted_kmc).toBe(REWRAPPED_ENVELOPE);
    expect(result.status.status).toBe('revoked');
    expect(result.accessGeneration).toBe(3);
  });

  it('fails fast through the status guard before touching the row', async () => {
    const transport = new CapturingTransport(() => ({
      status: 404,
      payload: { error: true, code: 'NOT_FOUND', message: 'Key not found' },
    }));
    const api = new PrincipalAccessApi(transport as never, ORG_API_KEY, stubWasm([]));
    await expect(
      api.revoke({
        policyKeyId: KEY_ID,
        principalAuthHash: PRINCIPAL_AUTH_HASH,
        slotCredentialId: SLOT_CREDENTIAL_ID,
        envelopeJson: ENVELOPE,
        grantor: GRANTOR,
      }),
    ).rejects.toThrow(SigbashSDKError);
    expect(transport.calls.some(call => call.method === 'DELETE')).toBe(false);
  });

  it('maps typed server rejections to their codes, and admin denials to AdminError', async () => {
    // The status read succeeds on the happy route, the revoke rejects.
    const mixed = new CapturingTransport(call => {
      if (call.method === 'GET') return { status: 200, payload: { policy_key_id: KEY_ID, principal_auth_hash: PRINCIPAL_AUTH_HASH, status: 'active', access_generation: 1 } };
      return { status: 409, payload: { error: true, code: 'ACCESS_STALE_GENERATION', message: 'stale' } };
    });
    const mixedApi = new PrincipalAccessApi(mixed as never, ORG_API_KEY, stubWasm([]));
    await expect(
      mixedApi.revoke({
        policyKeyId: KEY_ID,
        principalAuthHash: PRINCIPAL_AUTH_HASH,
        slotCredentialId: SLOT_CREDENTIAL_ID,
        envelopeJson: ENVELOPE,
        grantor: GRANTOR,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_STALE_GENERATION' });

    const forbidden = new CapturingTransport(() => ({
      status: 403,
      payload: { error: true, code: 'FORBIDDEN', message: 'Admin access required' },
    }));
    const forbiddenApi = new PrincipalAccessApi(forbidden as never, ORG_API_KEY, stubWasm([]));
    await expect(
      forbiddenApi.status(KEY_ID, PRINCIPAL_AUTH_HASH),
    ).rejects.toThrow(AdminError);
  });
});

describe('recovery rebind ceremony', () => {
  const PREVIOUS = { authHash: 'a'.repeat(64), slotCredentialId: 'b'.repeat(64) };
  const TWO_KEYS = ['7', '9'];
  const ENVELOPES: Record<string, string> = { '7': ENVELOPE, '9': ENVELOPE };

  function twoKeyServer(): RouteHandler {
    const generation: Record<string, number> = { '7': 1, '9': 4 };
    return call => {
      const keyMatch = call.input.match(/\/api\/v2\/sdk\/keys\/(\d+)\//);
      const key = keyMatch ? keyMatch[1] : '';
      if (call.method === 'POST' && call.input === '/api/v2/sdk/admin/users') {
        return { status: 200, payload: { success: true } };
      }
      if (call.method === 'POST' && /\/access$/.test(call.input)) {
        generation[key] += 1;
        const body = JSON.parse(call.body ?? '{}');
        return {
          status: 200,
          payload: {
            policy_key_id: key,
            principal_auth_hash: body.principal_auth_hash,
            status: 'active',
            access_generation: generation[key],
          },
        };
      }
      if (call.method === 'DELETE' && /\/access\/[0-9a-f]{64}$/.test(call.input)) {
        generation[key] += 1;
        return {
          status: 200,
          payload: {
            policy_key_id: key,
            principal_auth_hash: PREVIOUS.authHash,
            status: 'revoked',
            access_generation: generation[key],
          },
        };
      }
      if (call.method === 'GET' && /\/access\/[0-9a-f]{64}$/.test(call.input)) {
        return {
          status: 200,
          payload: {
            policy_key_id: key,
            principal_auth_hash: PREVIOUS.authHash,
            status: 'active',
            access_generation: generation[key],
          },
        };
      }
      if (call.method === 'POST' && /\/kmc\/rewrap$/.test(call.input)) {
        return { status: 200, payload: { success: true, key_id: key, access_generation: generation[key] } };
      }
      return { status: 404, payload: { error: true, code: 'NOT_FOUND', message: 'Key not found' } };
    };
  }

  it('provisions exactly one credential across all keys, grants first, then revokes', async () => {
    const { api, transport, wasmRecords } = makeApi(twoKeyServer());
    const result = await api.rebind({
      policyKeyIds: TWO_KEYS,
      envelopes: ENVELOPES,
      grantor: GRANTOR,
      previousPrincipal: PREVIOUS,
    });

    expect(transport.callsTo('POST', /\/admin\/users$/)).toHaveLength(1);
    expect(wasmRecords.filter(record => record.ceremony === 'add')).toHaveLength(2);
    expect(transport.callsTo('POST', /\/access$/)).toHaveLength(2);
    expect(transport.callsTo('DELETE', /\/access\/[0-9a-f]{64}$/)).toHaveLength(2);
    expect(wasmRecords.filter(record => record.ceremony === 'rewrap')).toHaveLength(2);

    // Every grant covers the same principal, and each key has its own row.
    const grantHashes = transport.callsTo('POST', /\/access$/)
      .map(call => JSON.parse(call.body as string).principal_auth_hash);
    expect(new Set(grantHashes).size).toBe(1);
    expect(grantHashes[0]).toBe(result.authHash);
    expect(new Set(result.grants.map(grant => grant.credential.userKey)).size).toBe(1);
    expect(result.grants.map(grant => grant.status.policy_key_id)).toEqual(TWO_KEYS);

    // Grants precede revokes: the organization never loses a principal.
    const firstRevoke = transport.calls.findIndex(call => call.method === 'DELETE');
    const lastGrant = Math.max(
      ...transport.callsTo('POST', /\/access$/).map(call => transport.calls.indexOf(call)),
    );
    expect(lastGrant).toBeLessThan(firstRevoke);

    // Every revoke names the replaced principal's slot.
    for (const record of wasmRecords.filter(r => r.ceremony === 'rewrap')) {
      expect(record.request.removeCredentialIds).toEqual([PREVIOUS.slotCredentialId]);
      expect(record.request.envelopeJson).toBeDefined();
    }
  });

  it('refuses to run without an envelope for every key, and with no keys', async () => {
    const { api } = makeApi(twoKeyServer());
    await expect(
      api.rebind({
        policyKeyIds: TWO_KEYS,
        envelopes: { '7': ENVELOPE },
        grantor: GRANTOR,
        previousPrincipal: PREVIOUS,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      api.rebind({
        policyKeyIds: [],
        envelopes: {},
        grantor: GRANTOR,
        previousPrincipal: PREVIOUS,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });

  it('never sends secret material across the whole composite run', async () => {
    const { api, transport } = makeApi(twoKeyServer());
    const result = await api.rebind({
      policyKeyIds: TWO_KEYS,
      envelopes: ENVELOPES,
      grantor: GRANTOR,
      previousPrincipal: PREVIOUS,
    });
    const sent = transport.bodies();
    for (const secret of secretFragments(result)) {
      expect(sent).not.toContain(secret);
    }
    expect(sent).not.toContain('SIGPRINC');
  });
});

describe('status and list reads', () => {
  it('parses the status view and rejects unknown states fail-closed', async () => {
    const { api } = makeApi();
    const view = await api.status(KEY_ID, 'd'.repeat(64));
    expect(view).toEqual({
      policy_key_id: KEY_ID,
      principal_auth_hash: 'd'.repeat(64),
      status: 'active',
      access_generation: 2,
    });

    const weird = new CapturingTransport(() => ({
      status: 200,
      payload: { policy_key_id: KEY_ID, principal_auth_hash: 'd'.repeat(64), status: 'archived', access_generation: 2 },
    }));
    const weirdApi = new PrincipalAccessApi(weird as never, ORG_API_KEY, stubWasm([]));
    await expect(weirdApi.status(KEY_ID, 'd'.repeat(64))).rejects.toMatchObject({ code: 'SERVER_ERROR' });
  });

  it('lists access rows as auth hashes and states only', async () => {
    const withRows: RouteHandler = call => {
      if (call.method === 'GET' && call.input === `/api/v2/sdk/keys/${KEY_ID}/access`) {
        return {
          status: 200,
          payload: [
            { policy_key_id: KEY_ID, principal_auth_hash: 'd'.repeat(64), status: 'active', access_generation: 2 },
            { policy_key_id: KEY_ID, principal_auth_hash: 'e'.repeat(64), status: 'revoked', access_generation: 4 },
          ],
        };
      }
      return happyServer()(call);
    };
    const { api, transport } = makeApi(withRows);
    const rows = await api.list(KEY_ID);
    expect(transport.callsTo('GET', /\/access$/)).toHaveLength(1);
    expect(rows).toHaveLength(2);
    expect(rows[0].status).toBe('active');
    expect(rows[1].status).toBe('revoked');
    for (const row of rows) {
      expect(Object.keys(row).sort()).toEqual(
        ['access_generation', 'policy_key_id', 'principal_auth_hash', 'status'],
      );
    }
  });
});

describe('wasm seam contract', () => {
  it('fails closed when the binary is not loaded', async () => {
    const seam = defaultPrincipalAccessWasm();
    await expect(
      seam.addPrincipalSlot({
        envelopeJson: ENVELOPE,
        selectedAuthMode: 'api',
        credentialId: 'x',
        authSecret: 'y',
        principalPublicKeyHex: '02' + 'a'.repeat(64),
        newCredentialId: 'z',
      }),
    ).rejects.toThrow(WasmError);
  });
});

describe('hygiene pins', () => {
  it('never imports the shared-execution-credential domain', async () => {
    const { readFileSync } = await import('node:fs');
    const { resolve, join } = await import('node:path');
    const source = readFileSync(resolve(join(__dirname, 'principalAccess.ts')), 'utf8');
    expect(source).not.toContain("from './wallet/executionCredential'");
    expect(source).not.toContain('SIGAEXEC1');
  });
});
