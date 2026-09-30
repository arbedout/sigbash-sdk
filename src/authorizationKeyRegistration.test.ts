/**
 * Key-registration shape tests (Tier 0 — no server, no real WASM).
 *
 * Two container shapes exist and cannot be mixed:
 *   - the signing shape: the legacy registration payload, byte-identical
 *     when no key-model declaration is made;
 *   - the identifier shape: an authorization-only key that registers with a
 *     key-model declaration and WITHOUT client_keys / h1 / key_hash, whose
 *     container's aggregate material is the client's own key.
 *
 * The WASM boundary is a faithful-shaped stub: it asserts the inputs the
 * SDK hands it and returns a well-formed container. Container construction
 * correctness inside the binary is covered by the native wasm suite — these
 * tests never claim it. The socket seam is a fake with real listener
 * semantics so the MuSig2 key-request leg can be exercised end to end.
 */

import { SigbashClient, SigbashSDKError } from './index';
import { decryptKMCEnvelope } from './crypto';
import { isIdentifierKeyScheme, keyCanSign, keyModelMetadataOf } from './authorization/keyModel';

// ---------------------------------------------------------------------------
// Socket seam: a fake SigbashSocket with real listener semantics.
// ---------------------------------------------------------------------------

interface RecordedRequest {
  event: string;
  payload: Record<string, unknown>;
}

const mockRequest = jest.fn();
const mockRawEmit = jest.fn();

/**
 * Connection state a newly constructed fake socket reports. Tests that pin
 * handshake ordering flip this to false so the client must wait for the
 * connect event before proceeding; the default true models the connected
 * socket the immediate request() semantics already imply.
 */
let mockSocketConnectedOnCreate = true;
const mockRawSockets: Record<string, unknown>[] = [];

interface ListenerEntry {
  event: string;
  fn: (payload: unknown) => void;
  once: boolean;
}

const socketListeners: ListenerEntry[] = [];

jest.mock('./socket', () => ({
  SigbashSocket: class {
    rawSocket: Record<string, unknown>;
    constructor() {
      this.rawSocket = {
        connected: mockSocketConnectedOnCreate,
        on: (event: string, fn: (payload: unknown) => void) => {
          socketListeners.push({ event, fn, once: false });
        },
        off: (event: string, fn: (payload: unknown) => void) => {
          const idx = socketListeners.findIndex(l => l.event === event && l.fn === fn);
          if (idx >= 0) socketListeners.splice(idx, 1);
        },
        once: (event: string, fn: (payload: unknown) => void) => {
          socketListeners.push({ event, fn, once: true });
        },
        emit: mockRawEmit,
        __sigbashEmitWrapped__: false,
      };
      mockRawSockets.push(this.rawSocket);
    }
    async request(event: string, payload: unknown) {
      return mockRequest(event, payload);
    }
    disconnect(): void {}
  },
}));

function recordedRequests(): RecordedRequest[] {
  return mockRequest.mock.calls.map(([event, payload]) => ({
    event,
    payload: payload as Record<string, unknown>,
  }));
}

function emitTo(event: string, payload: unknown): void {
  for (let i = socketListeners.length - 1; i >= 0; i--) {
    const entry = socketListeners[i];
    if (entry.event !== event) continue;
    if (entry.once) socketListeners.splice(i, 1);
    entry.fn(payload);
  }
}

// ---------------------------------------------------------------------------
// WASM boundary stub + server metadata transport
// ---------------------------------------------------------------------------

const CLIENT_PRIVATE_KEY_HEX = '11'.repeat(32);
const CLIENT_PUBKEY_HEX = '02' + 'ab'.repeat(32);
const SERVER_DESCRIPTOR_XPUB = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB';
const SERVER_FINGERPRINT = '5b97bc12';
const SERVER_BASE_PATH = 'm/86h/1h/0h/0';
const POLICY_ROOT = 'aa'.repeat(32);
const REBUILT_ROOT = 'bb'.repeat(32);
const TWEAKED_KEY_HEX = 'cd'.repeat(32);
const BIP328_XPUB = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB';
const P2TR_ADDRESS = 'bc1ptest';

let aggregateKMCInput: Record<string, unknown> | undefined;

// A minimal well-formed PSBT (magic + global map with an empty unsigned
// transaction) — enough for the client's own input-count preflight.
const PSBT_BASE64 = Buffer.from(
  '70736274ff' + '0100' + '0a' + '02000000000000000000' + '00',
  'hex'
).toString('base64');

const registerResponse = { key_id: '0' };

function buildContainerKMCJSON(overrides: Record<string, unknown> = {}): string {
  const container = {
    key_type: 'kmc',
    version: 'b5a91668',
    participants: [
      {
        key: '03' + '99'.repeat(32),
        derivation_path: `${SERVER_BASE_PATH}/1234567890`,
        source: 'server',
        master_key_fingerprint: SERVER_FINGERPRINT,
        master_xpub: SERVER_DESCRIPTOR_XPUB,
      },
      {
        key: CLIENT_PUBKEY_HEX,
        derivation_path: 'm/0/0',
        source: 'client',
        private_key_hex: CLIENT_PRIVATE_KEY_HEX,
      },
    ],
    poet_policy_json: JSON.stringify({ compiled: true }),
    policy_root_hex: REBUILT_ROOT,
    aggregate_public_key: TWEAKED_KEY_HEX,
    internal_public_key: CLIENT_PUBKEY_HEX,
    bip328_xpub: BIP328_XPUB,
    p2tr_address: P2TR_ADDRESS,
    credential_id: 'aa'.repeat(32),
    vanity_id: 'stub-vanity',
    timestamp: 1700000000,
    network: 'signet',
    policy_commitment: { policy_root: Buffer.from(REBUILT_ROOT, 'hex'), tseitin_cnf: { clauses: [] } },
    ...overrides,
  };
  return JSON.stringify(container);
}

let buildKMCInput: Record<string, unknown> | undefined;
let buildKMCResult: string;

function installWasmStubs(): void {
  (globalThis as Record<string, unknown>)['SigbashWASM_GenerateClientKeyMaterial'] = (input: string) => {
    if (input && input !== '{}') {
      const parsed = JSON.parse(input) as { private_key_hex?: string };
      if (parsed.private_key_hex) {
        throw new Error('stub only supports auto-generation');
      }
    }
    return JSON.stringify({
      private_key_hex: CLIENT_PRIVATE_KEY_HEX,
      public_key_hex: CLIENT_PUBKEY_HEX,
      xonly_pubkey_hex: CLIENT_PUBKEY_HEX.slice(2),
      h1_hex: '11'.repeat(32),
      key_hash_hex: '22'.repeat(32),
    });
  };

  (globalThis as Record<string, unknown>)['SigbashWASM_CompilePOETPolicy'] = (input: string) => {
    const parsed = JSON.parse(input) as Record<string, unknown>;
    expect(parsed['policy']).toBeDefined();
    expect(parsed['seed_hex']).toBeDefined();
    expect(parsed['credential_id']).toBeDefined();
    return JSON.stringify({
      policy_root: POLICY_ROOT,
      compiled_policy_json: JSON.stringify({ compiled: true }),
    });
  };

  (globalThis as Record<string, unknown>)['SigbashWASM_BuildAuthorizationKMC'] = (input: string) => {
    buildKMCInput = JSON.parse(input) as Record<string, unknown>;
    return buildKMCResult;
  };

  (globalThis as Record<string, unknown>)['SigbashWASM_AggregateAndBuildKMC'] = (input: string) => {
    aggregateKMCInput = JSON.parse(input) as Record<string, unknown>;
    return JSON.stringify({
      kmc_json: buildContainerKMCJSON(),
      aggregate_public_key_hex: TWEAKED_KEY_HEX,
      internal_public_key_hex: CLIENT_PUBKEY_HEX,
      p2tr_address: P2TR_ADDRESS,
      bip328_xpub: BIP328_XPUB,
      bip328_descriptor: `rawtr(${TWEAKED_KEY_HEX})`,
      policy_root_hex: REBUILT_ROOT,
      client_key_commitment_h1: '11'.repeat(32),
      client_key_hash: '22'.repeat(32),
    });
  };
}

const minimalPolicy = {
  version: '1.1',
  policy: {
    type: 'operator',
    operator: 'AND',
    children: [{
      type: 'condition',
      conditionType: 'OUTPUT_VALUE',
      conditionParams: { selector: 'ALL', operator: 'LTE', value: 100000 },
    }],
  },
};

const CREDENTIALS = {
  apiKey: '11'.repeat(32),
  userKey: '22'.repeat(32),
  userSecretKey: '33'.repeat(32),
};

function makeClient(): SigbashClient {
  return new SigbashClient({
    ...CREDENTIALS,
    serverUrl: 'http://localhost:19999',
  });
}

beforeEach(() => {
  mockRequest.mockReset();
  mockRawEmit.mockReset();
  socketListeners.length = 0;
  mockSocketConnectedOnCreate = true;
  mockRawSockets.length = 0;
  buildKMCInput = undefined;
  aggregateKMCInput = undefined;

  mockRequest.mockImplementation((event: string) => {
    if (event === 'register_key_with_hash') {
      return Promise.resolve(registerResponse);
    }
    return Promise.resolve({});
  });

  // The MuSig2 key-request leg: the fake server answers the raw emit.
  mockRawEmit.mockImplementation((event: string) => {
    if (event === 'submit_key_request') {
      setTimeout(() => {
        emitTo('key_request_response', {
          data: { partial_pub_key: [{ candidate_key: `[${SERVER_FINGERPRINT}/86h/1h/0h/0]${SERVER_DESCRIPTOR_XPUB}` }] },
        });
      }, 0);
    }
    return undefined;
  });

  installWasmStubs();

  buildKMCResult = JSON.stringify({
    kmc_json: buildContainerKMCJSON(),
    aggregate_public_key_hex: TWEAKED_KEY_HEX,
    internal_public_key_hex: CLIENT_PUBKEY_HEX,
    p2tr_address: P2TR_ADDRESS,
    bip328_xpub: BIP328_XPUB,
    bip328_descriptor: `rawtr(${TWEAKED_KEY_HEX})`,
    policy_root_hex: REBUILT_ROOT,
  });

  global.fetch = jest.fn(async (input: unknown) => {
    const url = typeof input === 'string' ? input : String((input as RequestInfo));
    if (url.includes('/api/v2/signing_key')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          fingerprint: SERVER_FINGERPRINT,
          base_path: SERVER_BASE_PATH,
          server_signing_public_key: SERVER_DESCRIPTOR_XPUB,
          network: 'signet',
        }),
      } as unknown as Response;
    }
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as unknown as typeof fetch;
});

afterEach(() => {
  delete (globalThis as Record<string, unknown>)['SigbashWASM_GenerateClientKeyMaterial'];
  delete (globalThis as Record<string, unknown>)['SigbashWASM_CompilePOETPolicy'];
  delete (globalThis as Record<string, unknown>)['SigbashWASM_BuildAuthorizationKMC'];
  delete (globalThis as Record<string, unknown>)['SigbashWASM_AggregateAndBuildKMC'];
  delete (globalThis as Record<string, unknown>)['SigbashWASM_SignPSBTBlind'];
});

function registerPayload(): Record<string, unknown> {
  const calls = recordedRequests().filter(r => r.event === 'register_key_with_hash');
  expect(calls).toHaveLength(1);
  return calls[0].payload;
}

// ---------------------------------------------------------------------------
// Identifier-shape registration
// ---------------------------------------------------------------------------

describe('identifier-shape registration (descriptor_derived)', () => {
  it('registers with the declaration and no signing-shaped fields', async () => {
    const client = makeClient();
    try {
      const result = await client.createKey({
        policy: minimalPolicy,
        network: 'signet',
        require2FA: false,
        keyScheme: 'descriptor_derived',
        keyIdentifier: 'treasury-identity-1',
      });

      const payload = registerPayload();
      // The identifier shape carries the declaration...
      expect(payload['key_scheme']).toBe('descriptor_derived');
      expect(payload['key_origin']).toBe('sigbash');
      expect(payload['key_capabilities']).toEqual(['transaction_authorize']);
      // ...and none of the signing-shaped fields.
      expect(payload['client_keys']).toBeUndefined();
      expect(payload['client_key_commitment_h1']).toBeUndefined();
      expect(payload['client_key_hash']).toBeUndefined();
      expect(payload['enc_kek2']).toBeTruthy();
      expect(payload['encrypted_key_material']).toBeTruthy();

      // The post-rebuild root is what gets registered.
      expect(payload['policy_root']).toBe(REBUILT_ROOT);

      // Display metadata: authorization-only role from the stamped container.
      expect(result.capabilities).toEqual(['transaction_authorize']);
      expect(result.keyRole).toBe('authorization_only');

      // The WASM build received the authorization-only inputs: no server
      // partial pub key JSON (no key request was made) and the metadata triple.
      expect(buildKMCInput).toBeDefined();
      expect(buildKMCInput!['server_partial_pub_key_json']).toBeUndefined();
      expect(buildKMCInput!['server_fingerprint']).toBe(SERVER_FINGERPRINT);
      expect(buildKMCInput!['server_base_path']).toBe(SERVER_BASE_PATH);
      expect(buildKMCInput!['server_signing_xpub']).toBe(SERVER_DESCRIPTOR_XPUB);
      expect(buildKMCInput!['client_private_key_hex']).toBe(CLIENT_PRIVATE_KEY_HEX);
      expect(buildKMCInput!['compiled_policy_json']).toBe(JSON.stringify({ compiled: true }));
      expect(buildKMCInput!['policy_root_hex']).toBe(POLICY_ROOT);

      // No MuSig2 key request was emitted — the identifier shape never
      // touches the key-request ceremony.
      const keyRequests = mockRawEmit.mock.calls.filter(([event]) => event === 'submit_key_request');
      expect(keyRequests).toHaveLength(0);
    } finally {
      client.disconnect();
    }
  });

  it('seals the declared key model and the client identifier into the container', async () => {
    const client = makeClient();
    try {
      await client.createKey({
        policy: minimalPolicy,
        network: 'signet',
        require2FA: false,
        keyScheme: 'client_chosen_identifier',
        keyIdentifier: 'treasury-identity-1',
      });

      const payload = registerPayload();
      const envelope = JSON.parse(payload['encrypted_key_material'] as string);
      const sealed = await decryptKMCEnvelope(envelope, CREDENTIALS.apiKey, CREDENTIALS.userKey, CREDENTIALS.userSecretKey);
      const container = sealed as Record<string, unknown>;
      expect(container['scheme']).toBe('client_chosen_identifier');
      expect(container['origin']).toBe('sigbash');
      expect(container['capabilities']).toEqual(['transaction_authorize']);
      expect(container['key_identifier']).toBe('treasury-identity-1');

      // The identifier reaches the server only sealed: the plaintext payload
      // never carries it.
      expect(JSON.stringify(payload)).not.toContain('treasury-identity-1');
    } finally {
      client.disconnect();
    }
  });

  it('maps a policy-setup failure to POLICY_SETUP_FAILED', async () => {
    buildKMCResult = JSON.stringify({ error: 'policy setup failed: unresolved placeholder class' });
    const client = makeClient();
    try {
      await expect(
        client.createKey({
          policy: minimalPolicy,
          network: 'signet',
          require2FA: false,
          keyScheme: 'descriptor_derived',
        })
      ).rejects.toMatchObject({ code: 'POLICY_SETUP_FAILED' });
    } finally {
      client.disconnect();
    }
  });

  it('maps a container-build failure to KEY_AGG_FAILED', async () => {
    buildKMCResult = JSON.stringify({ error: 'seal gate failed' });
    const client = makeClient();
    try {
      await expect(
        client.createKey({
          policy: minimalPolicy,
          network: 'signet',
          require2FA: false,
          keyScheme: 'descriptor_derived',
        })
      ).rejects.toMatchObject({ code: 'KEY_AGG_FAILED' });
    } finally {
      client.disconnect();
    }
  });

  it('refuses an unknown keyScheme before any network work', async () => {
    const client = makeClient();
    try {
      await expect(
        client.createKey({
          policy: minimalPolicy,
          network: 'signet',
          require2FA: false,
          keyScheme: 'ed25519' as never,
        })
      ).rejects.toMatchObject({ code: 'INVALID_KEY_SCHEME' });
      expect(mockRequest.mock.calls).toHaveLength(0);
      expect(buildKMCInput).toBeUndefined();
    } finally {
      client.disconnect();
    }
  });
});

// ---------------------------------------------------------------------------
// Signing-shape registration: byte-identity pin
// ---------------------------------------------------------------------------

// The /api/v2/signing_key fetch is PoP-verified over REST, and the PoP
// pubkey only exists server-side once the socket connect handshake has
// bootstrapped it (first-user auto-registration persists it at connect
// time). These tests pin that the handshake strictly precedes the fetch —
// the failure mode on a fresh org is a deterministic PoP rejection (401)
// when the fetch runs first.
describe('authorization registration ordering (handshake before REST fetch)', () => {
  it('awaits the socket connect handshake before fetching server signing key info', async () => {
    // Start the socket disconnected: the client must wait for the connect
    // event before any REST traffic.
    mockSocketConnectedOnCreate = false;
    const order: string[] = [];
    global.fetch = jest.fn(async () => {
      order.push('rest_fetch');
      return {
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          fingerprint: SERVER_FINGERPRINT,
          base_path: SERVER_BASE_PATH,
          server_signing_public_key: SERVER_DESCRIPTOR_XPUB,
          network: 'signet',
        }),
      } as unknown as Response;
    }) as unknown as typeof fetch;

    const client = makeClient();
    const done = client.createKey({
      policy: minimalPolicy,
      network: 'signet',
      require2FA: false,
      keyScheme: 'descriptor_derived',
      keyIdentifier: 'ordering-probe-1',
    });

    // Let the flow reach the handshake wait: the socket then exists but is
    // not connected, and no REST fetch may have been issued.
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(mockRawSockets).toHaveLength(1);
    expect(mockRawSockets[0]['connected']).toBe(false);
    (mockRawSockets[0]['on'] as (event: string, fn: () => void) => void)(
      'connect', () => order.push('handshake'));
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(order).toEqual([]);

    setImmediate(() => emitTo('connect', undefined));
    const result = await done;
    expect(order).toEqual(['handshake', 'rest_fetch']);

    const payload = registerPayload();
    expect(payload['key_scheme']).toBe('descriptor_derived');
    expect(result.keyId).toBe('0');
  });

  it('does not issue the REST fetch while the handshake is outstanding', async () => {
    mockSocketConnectedOnCreate = false;
    const fetchSpy = jest.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        fingerprint: SERVER_FINGERPRINT,
        base_path: SERVER_BASE_PATH,
        server_signing_public_key: SERVER_DESCRIPTOR_XPUB,
        network: 'signet',
      }),
    }) as unknown as Response) as unknown as typeof fetch;
    global.fetch = fetchSpy;

    const client = makeClient();
    const done = client.createKey({
      policy: minimalPolicy,
      network: 'signet',
      require2FA: false,
      keyScheme: 'descriptor_derived',
    });

    await new Promise(resolve => setTimeout(resolve, 25));
    expect(fetchSpy).not.toHaveBeenCalled();

    // Complete the handshake; the flow then proceeds to the fetch and the
    // full registration.
    emitTo('connect', undefined);
    await done;
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(registerPayload()['key_scheme']).toBe('descriptor_derived');
  });
});

describe('signing-shape registration', () => {
  it('the undeclared payload is byte-identical to the declared one minus its declaration fields', async () => {
    const runCreate = async (keyScheme?: string) => {
      const callsBefore = mockRequest.mock.calls.length;
      const client = makeClient();
      try {
        await client.createKey({
          policy: minimalPolicy,
          network: 'signet',
          require2FA: false,
          ...(keyScheme !== undefined ? { keyScheme } : {}),
        } as Parameters<SigbashClient['createKey']>[0]);
      } finally {
        client.disconnect();
      }
      const call = mockRequest.mock.calls[callsBefore] as unknown as [
        string,
        Record<string, unknown>,
      ];
      expect(call[0]).toBe('register_key_with_hash');
      return call[1];
    };

    const undeclared = await runCreate();
    expect(undeclared['key_scheme']).toBeUndefined();
    expect(undeclared['key_origin']).toBeUndefined();
    expect(undeclared['key_capabilities']).toBeUndefined();

    const declared = await runCreate('secp256k1_schnorr');
    expect(declared['key_scheme']).toBe('secp256k1_schnorr');
    expect(declared['key_origin']).toBe('sigbash');
    expect(declared['key_capabilities']).toEqual(['bitcoin_sign']);

    // Byte-identity pin: strip the declaration fields the caller explicitly
    // requested and the two payloads must be exactly equal — the absent
    // declaration is the byte-identical legacy signing registration. The
    // envelope fields are the run's own randoms (fresh envelope ID, nonces,
    // timestamps) and are pinned to presence on both sides instead: both
    // payloads are produced by the identical build-and-seal code path.
    const stripVolatile = (payload: Record<string, unknown>) => {
      const copy = { ...payload };
      delete copy['encrypted_key_material'];
      delete copy['enc_kek2'];
      return copy;
    };
    expect(undeclared['encrypted_key_material']).toBeTruthy();
    expect(undeclared['enc_kek2']).toBeTruthy();
    expect(declared['encrypted_key_material']).toBeTruthy();
    expect(declared['enc_kek2']).toBeTruthy();
    const stripped = stripVolatile(declared);
    delete stripped['key_scheme'];
    delete stripped['key_origin'];
    delete stripped['key_capabilities'];
    expect(JSON.stringify(stripped)).toBe(JSON.stringify(stripVolatile(undeclared)));
  });

  it('the signing shape still rides the MuSig2 key request', async () => {
    const client = makeClient();
    try {
      await client.createKey({
        policy: minimalPolicy,
        network: 'signet',
        require2FA: false,
      });
      const payload = registerPayload();
      expect(Array.isArray(payload['client_keys'])).toBe(true);
      expect(payload['client_key_commitment_h1']).toBe('11'.repeat(32));
      expect(payload['client_key_hash']).toBe('22'.repeat(32));
      const keyRequests = mockRawEmit.mock.calls.filter(([event]) => event === 'submit_key_request');
      expect(keyRequests.length).toBeGreaterThan(0);
    } finally {
      client.disconnect();
    }
  });
});

// ---------------------------------------------------------------------------
// signPSBT structural refusal
// ---------------------------------------------------------------------------

const identifierContainer = JSON.stringify({
  scheme: 'descriptor_derived',
  origin: 'sigbash',
  capabilities: ['transaction_authorize'],
  internal_public_key: CLIENT_PUBKEY_HEX,
});

const signingContainer = JSON.stringify({
  scheme: 'secp256k1_schnorr',
  origin: 'sigbash',
  capabilities: ['bitcoin_sign'],
});

describe('signPSBT structural refusal', () => {
  it('refuses an authorization-only container before any socket call', async () => {
    (globalThis as Record<string, unknown>)['SigbashWASM_SignPSBTBlind'] = () =>
      Promise.reject(new Error('SENTINEL_PIPELINE_STOP'));
    const client = makeClient();
    try {
      await expect(
        client.signPSBT({
          keyId: '0',
          psbtBase64: PSBT_BASE64,
          kmcJSON: identifierContainer,
          network: 'signet',
          require2FA: false,
        })
      ).rejects.toMatchObject({ code: 'KEY_NOT_SIGNING_CAPABLE' });

      // Zero socket activity: no preflight request, no raw emit, no nonce
      // exchange — the refusal is purely local on declared state.
      expect(mockRequest.mock.calls).toHaveLength(0);
      expect(mockRawEmit.mock.calls).toHaveLength(0);
    } finally {
      client.disconnect();
    }
  });

  it('passes signing-capable containers through to the pipeline', async () => {
    (globalThis as Record<string, unknown>)['SigbashWASM_SignPSBTBlind'] = () =>
      Promise.reject(new Error('SENTINEL_PIPELINE_STOP'));

    const client = makeClient();
    try {
      await expect(
        client.signPSBT({
          keyId: '0',
          psbtBase64: PSBT_BASE64,
          kmcJSON: signingContainer,
          network: 'signet',
          require2FA: false,
        })
      ).rejects.toThrow('SENTINEL_PIPELINE_STOP');
    } finally {
      client.disconnect();
    }
  });

  it('passes legacy containers (no declared key model) through to the pipeline', async () => {
    (globalThis as Record<string, unknown>)['SigbashWASM_SignPSBTBlind'] = () =>
      Promise.reject(new Error('SENTINEL_PIPELINE_STOP'));

    const legacyContainer = JSON.stringify({ internal_public_key: CLIENT_PUBKEY_HEX });
    const client = makeClient();
    try {
      await expect(
        client.signPSBT({
          keyId: '0',
          psbtBase64: PSBT_BASE64,
          kmcJSON: legacyContainer,
          network: 'signet',
          require2FA: false,
        })
      ).rejects.toThrow('SENTINEL_PIPELINE_STOP');
    } finally {
      client.disconnect();
    }
  });
});

// ---------------------------------------------------------------------------
// Key-model helpers
// ---------------------------------------------------------------------------

describe('key model helpers', () => {
  it('classifies the identifier schemes and the signing scheme', () => {
    expect(isIdentifierKeyScheme('descriptor_derived')).toBe(true);
    expect(isIdentifierKeyScheme('client_chosen_identifier')).toBe(true);
    expect(isIdentifierKeyScheme('secp256k1_schnorr')).toBe(false);
  });

  it('decides signing capability from the declared model', () => {
    expect(keyCanSign(keyModelMetadataOf(JSON.parse(signingContainer)))).toBe(true);
    expect(keyCanSign(keyModelMetadataOf(JSON.parse(identifierContainer)))).toBe(false);
    // A legacy container (no declared model) keeps the signing default.
    expect(keyCanSign(keyModelMetadataOf(JSON.parse('{}')))).toBe(true);
  });
});
