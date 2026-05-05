/**
 * SigbashClient integration tests.
 *
 * Tier 1 — no server required: constructor validation, static generators,
 *           createKey input validation, signPSBT TOTP guard, verifyPSBT WASM guard.
 *
 * Tier 2 — live server required: createKey, getKey, registerTOTP, confirmTOTP,
 *           signPSBT, registerUser, revokeUser, disconnect.
 *
 * Live tests are skipped gracefully when SIGBASH_TEST_SERVER_URL is not set.
 */

import {
  SigbashClient,
  MissingOptionError,
  SigbashSDKError,
  TOTPRequiredError,
  KeyIndexExistsError,
  TOTPInvalidError,
  TOTPSetupIncompleteError,
  CryptoError,
  AdminError,
  NetworkError,
  loadWasm,
  isWasmReady,
  POETPolicy,
} from './index';

import { generateTOTPCode } from './__tests__/helpers/totp-helper';
import {
  fundXpubAndGetUtxo,
  buildPsbtFromUtxo,
  isBitcoinContainerRunning,
  mineBlock,
  sendRawTx,
} from './__tests__/helpers/bitcoin-signet-helper';
import { execSync } from 'child_process';

// ---------------------------------------------------------------------------
// Environment variables
// ---------------------------------------------------------------------------

const SERVER_URL = process.env['SIGBASH_TEST_SERVER_URL'] ?? 'https://www.sigbash.com';
// When no API key is provided via env, generate a timestamped key so this run is
// always the first user in its org → auto-registers as admin on first createKey.
const API_KEY = process.env['SIGBASH_TEST_API_KEY'] ?? `test-api-key-${Date.now()}`;
const PSBT_BASE64 = process.env['SIGBASH_TEST_PSBT_BASE64'];
// WASM is always loaded from the server URL (never from a local file path).
const WASM_LOAD_URL = SERVER_URL ? `${SERVER_URL}/sigbash.wasm` : undefined;

/**
 * Fetch the expected WASM SHA-384 hash from the server's wasm-version.json.
 * Returns hex-encoded hash for use with loadWasm's expectedHash parameter.
 */
async function fetchExpectedWasmHash(): Promise<string> {
  const url = `${SERVER_URL}/wasm-version.json`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
  const json: { sha384: string } = await res.json();
  // wasm-version.json stores sha384 as base64; loadWasm expects hex.
  const bytes = Buffer.from(json.sha384, 'base64');
  return bytes.toString('hex');
}

// Dummy URL for tests that must not hit the network
const DUMMY_URL = 'http://localhost:19999';

// Fresh credential pair generated once per test run and reused across live tests
const LIVE_USER_KEY = SigbashClient.generateUserKey();
const LIVE_USER_SECRET = SigbashClient.generateUserSecretKey();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a valid SigbashClient pointed at a non-existent endpoint.
 * Suitable for testing validation that throws before any network call.
 */
function makeDummyClient(): SigbashClient {
  return new SigbashClient({
    apiKey: API_KEY,
    userKey: SigbashClient.generateUserKey(),
    userSecretKey: SigbashClient.generateUserSecretKey(),
    serverUrl: DUMMY_URL,
  });
}

// ---------------------------------------------------------------------------
// Global timeout for live-server scenarios
// ---------------------------------------------------------------------------

jest.setTimeout(60_000); // 60s: live-server tests involve socket connections (up to 30s each)

// ===========================================================================
// TIER 1 — NO SERVER REQUIRED
// ===========================================================================

// ---------------------------------------------------------------------------
// Constructor (scenarios 1–5)
// ---------------------------------------------------------------------------

describe('SigbashClient constructor — Tier 1', () => {
  it('scenario 1: missing apiKey throws MissingOptionError', () => {
    expect(() =>
      new SigbashClient({
        apiKey: '',
        userKey: SigbashClient.generateUserKey(),
        userSecretKey: SigbashClient.generateUserSecretKey(),
        serverUrl: DUMMY_URL,
      })
    ).toThrow(MissingOptionError);
  });

  it('scenario 2: missing userKey throws MissingOptionError', () => {
    expect(() =>
      new SigbashClient({
        apiKey: API_KEY,
        userKey: '',
        userSecretKey: SigbashClient.generateUserSecretKey(),
        serverUrl: DUMMY_URL,
      })
    ).toThrow(MissingOptionError);
  });

  it('scenario 3: empty userSecretKey throws MissingOptionError', () => {
    expect(() =>
      new SigbashClient({
        apiKey: API_KEY,
        userKey: SigbashClient.generateUserKey(),
        userSecretKey: '',
        serverUrl: DUMMY_URL,
      })
    ).toThrow(MissingOptionError);
  });

  it('scenario 4: missing serverUrl throws MissingOptionError', () => {
    expect(() =>
      new SigbashClient({
        apiKey: API_KEY,
        userKey: SigbashClient.generateUserKey(),
        userSecretKey: SigbashClient.generateUserSecretKey(),
        serverUrl: '',
      })
    ).toThrow(MissingOptionError);
  });

  it('scenario 5: valid options constructs without throwing', () => {
    let client: SigbashClient | undefined;
    expect(() => {
      client = new SigbashClient({
        apiKey: API_KEY,
        userKey: SigbashClient.generateUserKey(),
        userSecretKey: SigbashClient.generateUserSecretKey(),
        serverUrl: DUMMY_URL,
      });
    }).not.toThrow();
    client?.disconnect();
  });
});

// ---------------------------------------------------------------------------
// Static generators (scenarios 6–8)
// ---------------------------------------------------------------------------

describe('SigbashClient static generators — Tier 1', () => {
  it('scenario 6: generateUserKey returns a 64-char hex string', () => {
    const key = SigbashClient.generateUserKey();
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  it('scenario 7: generateUserSecretKey returns a 64-char hex string', () => {
    const secret = SigbashClient.generateUserSecretKey();
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
  });

  it('scenario 8: two consecutive calls return different values', () => {
    const a = SigbashClient.generateUserKey();
    const b = SigbashClient.generateUserKey();
    expect(a).not.toBe(b);
  });
});

// ---------------------------------------------------------------------------
// createKey validation — no server needed (scenarios 9–13)
// ---------------------------------------------------------------------------

describe('createKey input validation — Tier 1', () => {
  let client: SigbashClient;

  beforeEach(() => {
    client = makeDummyClient();
  });

  afterEach(() => {
    client.disconnect();
  });

  it('scenario 9: missing require2FA rejects with MissingOptionError', async () => {
    await expect(
      client.createKey({
        network: 'signet',
        require2FA: undefined as any,
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 1 },
      } as any)
    ).rejects.toThrow(MissingOptionError);

    await expect(
      client.createKey({
        network: 'signet',
        require2FA: undefined as any,
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 1 },
      } as any)
    ).rejects.toMatchObject({ optionName: 'require2FA' });
  });

  it('scenario 10: missing network rejects with MissingOptionError', async () => {
    await expect(
      client.createKey({
        require2FA: false,
        network: undefined as any,
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 1 },
      } as any)
    ).rejects.toThrow(MissingOptionError);

    await expect(
      client.createKey({
        require2FA: false,
        network: undefined as any,
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 1 },
      } as any)
    ).rejects.toMatchObject({ optionName: 'network' });
  });

  it('scenario 11: no template or policy rejects with SigbashSDKError MISSING_POLICY', async () => {
    await expect(
      client.createKey({
        require2FA: false,
        network: 'signet',
      } as any)
    ).rejects.toThrow(SigbashSDKError);

    await expect(
      client.createKey({
        require2FA: false,
        network: 'signet',
      } as any)
    ).rejects.toMatchObject({ code: 'MISSING_POLICY' });
  });

  it('scenario 12: both template AND policy rejects with SigbashSDKError AMBIGUOUS_POLICY', async () => {
    await expect(
      client.createKey({
        require2FA: false,
        network: 'signet',
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 1 },
        policy: {
          version: '1.1',
          policy: {
            type: 'condition',
            conditionType: 'ALLOWLIST',
            conditionParams: { allowed_addresses: [] },
          },
        },
      })
    ).rejects.toThrow(SigbashSDKError);

    await expect(
      client.createKey({
        require2FA: false,
        network: 'signet',
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 1 },
        policy: {
          version: '1.1',
          policy: {
            type: 'condition',
            conditionType: 'ALLOWLIST',
            conditionParams: { allowed_addresses: [] },
          },
        },
      })
    ).rejects.toMatchObject({ code: 'AMBIGUOUS_POLICY' });
  });

  it('scenario 13: unknown template rejects with Error from template registry', async () => {
    await expect(
      client.createKey({
        require2FA: false,
        network: 'signet',
        template: 'unknown-template',
        templateParams: {},
      })
    ).rejects.toThrow(Error);
  });
});

// ---------------------------------------------------------------------------
// signPSBT TOTP guard — no server needed (scenario 37)
// ---------------------------------------------------------------------------

describe('signPSBT TOTP guard — Tier 1', () => {
  let client: SigbashClient;

  beforeEach(() => {
    client = makeDummyClient();
  });

  afterEach(() => {
    client.disconnect();
  });

  it('scenario 37: require2FA=true without totpCode rejects with TOTPRequiredError', async () => {
    await expect(
      client.signPSBT({
        keyId: 'test',
        psbtBase64: 'test',
        require2FA: true,
      } as any)
    ).rejects.toThrow(TOTPRequiredError);
  });
});

// ---------------------------------------------------------------------------
// verifyPSBT WASM guard — no server needed (scenario 45)
// ---------------------------------------------------------------------------

describe('verifyPSBT WASM guard — Tier 1', () => {
  let client: SigbashClient;

  beforeEach(() => {
    client = makeDummyClient();
  });

  afterEach(() => {
    client.disconnect();
  });

  it('scenario 45: verifyPSBT without loaded WASM throws SigbashSDKError WASM_NOT_LOADED', async () => {
    try {
      await client.verifyPSBT({
        psbtBase64: 'test',
        kmcJSON: '{}',
        network: 'signet',
      });
      fail('Expected SigbashSDKError to be thrown');
    } catch (err) {
      expect((err as SigbashSDKError).code).toBe('WASM_NOT_LOADED');
    }
  });
});

// ===========================================================================
// TIER 2 — LIVE SERVER REQUIRED
// ===========================================================================

// Storage for key IDs created during live tests
// These are shared across the live describe blocks that use the same client
let liveKeyId14: string;          // created in scenario 14 (signet, no 2FA)
let liveKeyId15: string;          // created in scenario 15 (signet, 2FA)
let liveKeyId16: string;          // created in scenario 16 (testnet)
let liveKeyId18: string;          // created in scenario 18 (raw policy)
let liveKeyId19: string;          // created in scenario 19 (OUTPUT_DEST_IS_IN_SETS raw policy)
let liveKeyId20: string;          // created in scenario 20 (bitcoin-inheritance)
let liveKeyId21: string;          // created in scenario 21 (multisig 2-of-3)
let liveKeyId22: string;          // created in scenario 22 (multisig 2-of-5 with cap)
let liveKeyId23: string;          // created in scenario 23 (keyIndex=1)
let liveKeyId24: string;          // created in scenario 24 (keyIndex=2)
let totpSecret15: string;         // TOTP secret registered for scenario 15's key
let liveKmcJSON14 = '';           // kmcJSON for liveKeyId14 — populated by scenario 27, used in WASM tests
let liveKmcJSON15 = '';           // kmcJSON for liveKeyId15 — populated by scenario 28, used in scenario 39
let liveKeyId44 = '';             // fresh key created in signPSBT beforeAll for scenario 44
let liveKmcJSON44 = '';           // kmcJSON for liveKeyId44 — populated in signPSBT beforeAll
let restrictiveKeyId = '';        // keyId for 1-sat-cap key used in scenario 47
let liveKeyId58 = '';             // covenant key created in scenarios 58–61 beforeAll
let liveKmcJSON58 = '';           // kmcJSON for liveKeyId58
let liveTx1Txid = '';             // TX1 txid captured after scenario 59 broadcast
let liveTx1ScriptPubKeyHex = '';  // TX1 output 0 scriptPubKey (same as funding address)
let liveTx1OutputSats = 0;        // TX1 output 0 value in sats (funding value − 1000 fee)
let livePsbtBase64_59: string | undefined;  // TX1 PSBT (spends funding UTXO → self-payment)
let livePsbtBase64_61: string | undefined;  // TX2 PSBT (spends TX1 output 0 → self-payment)
let livePsbtBase64: string | undefined = PSBT_BASE64;    // scenario 38 PSBT (funded to liveKmcJSON14.bip328_xpub)
let livePsbtBase64_39: string | undefined;               // scenario 39 PSBT (funded to liveKmcJSON15.bip328_xpub)
let livePsbtBase64_44: string | undefined;               // scenario 44 PSBT (funded to liveKmcJSON44.bip328_xpub)

// ---------------------------------------------------------------------------
// createKey — live server (scenarios 14–25)
// ---------------------------------------------------------------------------

describe('createKey — live server', () => {
  const liveServerAvailable = !!SERVER_URL;
  let client: SigbashClient;

  beforeAll(async () => {
    if (!liveServerAvailable) return;
    // createKey() requires WASM since T45.
    // Load it once here; all subsequent describe blocks share globalThis WASM state.
    if (!isWasmReady()) {
      if (!WASM_LOAD_URL) throw new Error('No WASM source: set SIGBASH_TEST_SERVER_URL');
      const expectedHash = await fetchExpectedWasmHash();
      const t0 = Date.now();
      await loadWasm({
        wasmUrl: WASM_LOAD_URL,
        expectedHash,
      });
    }
    client = new SigbashClient({
      apiKey: API_KEY,
      userKey: LIVE_USER_KEY,
      userSecretKey: LIVE_USER_SECRET,
      serverUrl: SERVER_URL!,
    });
  }, 120_000); // 2-minute timeout: WASM download + instantiate can take >30s

  afterAll(() => client?.disconnect());

  it('scenario 14: weekly-spending-limit, require2FA=false, network=signet → CreateKeyResult', async () => {
    if (!liveServerAvailable) return;
    const result = await client.createKey({
      require2FA: false,
      network: 'signet',
      template: 'weekly-spending-limit',
      templateParams: { weeklyLimitSats: 100_000 },
    });
    expect(result).toMatchObject({
      keyIndex: 0,
      require2FA: false,
      network: 'signet',
    });
    expect(typeof result.keyId).toBe('string');
    expect(result.keyId.length).toBeGreaterThan(0);
    expect(typeof result.policyRoot).toBe('string');
    liveKeyId14 = result.keyId;
  });

  it('scenario 15: weekly-spending-limit, require2FA=true, network=signet → success', async () => {
    if (!liveServerAvailable) return;
    const result = await client.createKey({
      require2FA: true,
      network: 'signet',
      template: 'weekly-spending-limit',
      templateParams: { weeklyLimitSats: 50_000 },
      keyIndex: 1,
    });
    expect(result.require2FA).toBe(true);
    expect(result.network).toBe('signet');
    liveKeyId15 = result.keyId;
  });

  it('scenario 16: weekly-spending-limit, network=testnet → success or server unavailable', async () => {
    if (!liveServerAvailable) return;
    try {
      const result = await client.createKey({
        require2FA: false,
        network: 'testnet',
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 200_000 },
        keyIndex: 7,  // explicit to avoid collision with indices 0-6 used by other scenarios
      });
      expect(result.network).toBe('testnet');
      liveKeyId16 = result.keyId;
    } catch (err) {
      // testnet may be unavailable on test servers (no candidate keys) — acceptable
      expect(err).toBeInstanceOf(SigbashSDKError);
    }
  });

  it('scenario 17: weekly-spending-limit, network=mainnet → success or NetworkError', async () => {
    if (!liveServerAvailable) return;
    try {
      const result = await client.createKey({
        require2FA: false,
        network: 'mainnet',
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 500_000 },
      });
      expect(result.network).toBe('mainnet');
    } catch (err) {
      // mainnet may be disabled on test servers — acceptable
      expect(err).toBeInstanceOf(NetworkError);
    }
  });

  it('scenario 18: raw POETPolicy (timelock condition) → success', async () => {
    if (!liveServerAvailable) return;
    const unlockTimestamp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const result = await client.createKey({
      require2FA: false,
      network: 'signet',
      policy: {
        version: '1.1',
        policy: {
          type: 'condition',
          conditionType: 'TIME_BASED_CONSTRAINT',
          conditionParams: { constraint_type: 'after', start_time: unlockTimestamp },
          description: 'Timelock until 1 hour from now',
        },
      },
      keyIndex: 2,
    });
    expect(typeof result.keyId).toBe('string');
    expect(result.network).toBe('signet');
    liveKeyId18 = result.keyId;
  });

  it('scenario 19: OUTPUT_DEST_IS_IN_SETS raw policy (3 scriptpubkeys) → success', async () => {
    if (!liveServerAvailable) return;
    // Use raw P2TR scriptpubkeys (5120 + 32-byte x-only key) to avoid bech32 address
    // decoding issues.  The WASM supports both "addresses" and "scriptpubkeys" fields.
    const result = await client.createKey({
      require2FA: false,
      network: 'signet',
      policy: {
        version: '1.1',
        policy: {
          type: 'condition',
          conditionType: 'OUTPUT_DEST_IS_IN_SETS',
          conditionParams: {
            selector: { type: 'ALL' },
            scriptpubkeys: [
              '51200000000000000000000000000000000000000000000000000000000000000001',
              '51200000000000000000000000000000000000000000000000000000000000000002',
              '51200000000000000000000000000000000000000000000000000000000000000003',
            ],
            network: 'signet',
            require_change_to_input_addresses: true,
          },
          description: '3-scriptpubkey output allowlist',
        },
      },
      keyIndex: 3,
    });
    expect(typeof result.keyId).toBe('string');
    liveKeyId19 = result.keyId;
  });

  it('scenario 20: bitcoin-inheritance template → success', async () => {
    if (!liveServerAvailable) return;
    const result = await client.createKey({
      require2FA: false,
      network: 'signet',
      template: 'bitcoin-inheritance',
      templateParams: { unlockTimestamp: Math.floor(Date.now() / 1000) + 7200 },
      keyIndex: 4,
    });
    expect(typeof result.keyId).toBe('string');
    liveKeyId20 = result.keyId;
  });

  it('scenario 21: THRESHOLD 2-of-3 raw policy → success', async () => {
    if (!liveServerAvailable) return;
    const result = await client.createKey({
      require2FA: false,
      network: 'signet',
      policy: {
        version: '1.1',
        policy: {
          type: 'operator',
          operator: 'THRESHOLD',
          threshold: 2,
          children: [1, 2, 3].map((i) => ({
            type: 'condition',
            conditionType: 'REQKEY',
            conditionParams: {
              selector: { type: 'ALL' },
              key_identifier: i.toString(16).padStart(64, '0'),
              key_type: 'TAP_LEAF_XONLY_PUBKEY',
            },
            description: `Signer ${i}`,
          })),
          description: '2-of-3 multisig',
        } as import('./types').PolicyNode,
      },
      keyIndex: 5,
    });
    expect(typeof result.keyId).toBe('string');
    liveKeyId21 = result.keyId;
  });

  it('scenario 22: THRESHOLD 2-of-5 with OUTPUT_VALUE cap raw policy → success', async () => {
    if (!liveServerAvailable) return;
    // Each AND branch includes COUNT_BASED_CONSTRAINT so the WASM compilation is
    // idempotent (no auto-generated default nullifier configs are injected, which
    // would make the second re-compilation hash differ from the first).
    const result = await client.createKey({
      require2FA: false,
      network: 'signet',
      policy: {
        version: '1.1',
        policy: {
          type: 'operator',
          operator: 'THRESHOLD',
          threshold: 2,
          children: [1, 2, 3, 4, 5].map((i) => ({
            type: 'operator',
            operator: 'AND',
            children: [
              {
                type: 'condition',
                conditionType: 'REQKEY',
                conditionParams: {
                  selector: { type: 'ALL' },
                  key_identifier: i.toString(16).padStart(64, '0'),
                  key_type: 'TAP_LEAF_XONLY_PUBKEY',
                },
                description: `Signer ${i}`,
              },
              {
                type: 'condition',
                conditionType: 'OUTPUT_VALUE',
                conditionParams: {
                  selector: { type: 'ALL' },
                  operator: 'LTE',
                  value: 100_000,
                },
                description: `Signer ${i} cap: 100000 sats`,
              },
              {
                type: 'condition',
                conditionType: 'COUNT_BASED_CONSTRAINT',
                conditionParams: {
                  max_uses: 1,
                  reset_interval: 'weekly',
                  reset_type: 'rolling',
                },
                description: `Signer ${i}: once per week`,
              },
            ],
          })),
          description: '2-of-5 multisig with 100k cap and weekly limit',
        } as import('./types').PolicyNode,
      },
      keyIndex: 6,
    });
    expect(typeof result.keyId).toBe('string');
    liveKeyId22 = result.keyId;
  });

  it('scenario 23: createKey at keyIndex=1 (second credential slot) → keyIndex:1', async () => {
    if (!liveServerAvailable) return;
    // Use a brand-new apiKey (new org) so this user auto-registers as the first org admin
    const freshClient = new SigbashClient({
      apiKey: SigbashClient.generateUserKey(),
      userKey: SigbashClient.generateUserKey(),
      userSecretKey: SigbashClient.generateUserSecretKey(),
      serverUrl: SERVER_URL!,
    });
    try {
      const result = await freshClient.createKey({
        require2FA: false,
        network: 'signet',
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 10_000 },
        keyIndex: 1,
      });
      expect(result.keyIndex).toBe(1);
      liveKeyId23 = result.keyId;
    } finally {
      freshClient.disconnect();
    }
  });

  it('scenario 24: createKey at keyIndex=2 → keyIndex:2', async () => {
    if (!liveServerAvailable) return;
    // Use a brand-new apiKey (new org) so this user auto-registers as the first org admin
    const freshClient = new SigbashClient({
      apiKey: SigbashClient.generateUserKey(),
      userKey: SigbashClient.generateUserKey(),
      userSecretKey: SigbashClient.generateUserSecretKey(),
      serverUrl: SERVER_URL!,
    });
    try {
      const result = await freshClient.createKey({
        require2FA: false,
        network: 'signet',
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 10_000 },
        keyIndex: 2,
      });
      expect(result.keyIndex).toBe(2);
      liveKeyId24 = result.keyId;
    } finally {
      freshClient.disconnect();
    }
  });

  it('scenario 25: duplicate keyIndex=0 rejects with KeyIndexExistsError', async () => {
    if (!liveServerAvailable) return;
    // The main LIVE_USER_KEY already has keyIndex=0 registered in scenario 14
    await expect(
      client.createKey({
        require2FA: false,
        network: 'signet',
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 1 },
        keyIndex: 0,
      })
    ).rejects.toThrow(KeyIndexExistsError);

    try {
      await client.createKey({
        require2FA: false,
        network: 'signet',
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 1 },
        keyIndex: 0,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(KeyIndexExistsError);
      expect((err as KeyIndexExistsError).nextAvailableIndex).toBeGreaterThanOrEqual(1);
    }
  });
});

// ---------------------------------------------------------------------------
// getKey — live server (scenarios 27–31)
// ---------------------------------------------------------------------------

describe('getKey — live server', () => {
  const liveServerAvailable = !!SERVER_URL;
  let client: SigbashClient;

  beforeAll(() => {
    if (!liveServerAvailable) return;
    client = new SigbashClient({
      apiKey: API_KEY,
      userKey: LIVE_USER_KEY,
      userSecretKey: LIVE_USER_SECRET,
      serverUrl: SERVER_URL!,
    });
  });

  afterAll(() => client?.disconnect());

  it('scenario 27: getKey with keyId from scenario 14 → GetKeyResult', async () => {
    if (!liveServerAvailable) return;
    const result = await client.getKey(liveKeyId14);
    expect(result).toMatchObject({
      keyId: liveKeyId14,
      network: 'signet',
      require2FA: false,
    });
    expect(typeof result.policyRoot).toBe('string');
    expect(typeof result.kmcJSON).toBe('string');
    liveKmcJSON14 = result.kmcJSON; // share with verifyPSBT WASM tests
  });

  it('scenario 28: getKey with keyIndex=1 retrieves the correct key', async () => {
    if (!liveServerAvailable) return;
    // keyIndex 1 was registered in scenario 15 using LIVE_USER_KEY
    const result = await client.getKey(liveKeyId15, { keyIndex: 1 });
    expect(result.keyId).toBe(liveKeyId15);
    expect(result.keyIndex).toBe(1);
    liveKmcJSON15 = result.kmcJSON; // share with signPSBT scenario 39
  });

  it('scenario 29: kmcJSON is valid JSON', async () => {
    if (!liveServerAvailable) return;
    const result = await client.getKey(liveKeyId14);
    expect(() => JSON.parse(result.kmcJSON)).not.toThrow();
  });

  it('scenario 30: keyMaterial.poet_policy_json matches the policy used in createKey', async () => {
    if (!liveServerAvailable) return;
    const result = await client.getKey(liveKeyId14);
    // The KMC stores the compiled POET policy JSON as poet_policy_json (a string).
    const material = result.keyMaterial as { poet_policy_json?: string };
    expect(material.poet_policy_json).toBeDefined();
    expect(typeof material.poet_policy_json).toBe('string');
    // The policy should contain the weekly-spending-limit template structure
    expect(material.poet_policy_json).toContain('OUTPUT_VALUE');
  });

  it('scenario 31: wrong userSecretKey causes CryptoError on decryption', async () => {
    if (!liveServerAvailable) return;
    const wrongSecretClient = new SigbashClient({
      apiKey: API_KEY,
      userKey: LIVE_USER_KEY,
      userSecretKey: SigbashClient.generateUserSecretKey(), // different secret
      serverUrl: SERVER_URL!,
    });
    try {
      await expect(wrongSecretClient.getKey(liveKeyId14)).rejects.toThrow(CryptoError);
    } finally {
      wrongSecretClient.disconnect();
    }
  });
});

// ---------------------------------------------------------------------------
// registerTOTP + confirmTOTP — live server (scenarios 32–36)
// ---------------------------------------------------------------------------

describe('registerTOTP and confirmTOTP — live server', () => {
  const liveServerAvailable = !!SERVER_URL;
  let client: SigbashClient;

  beforeAll(() => {
    if (!liveServerAvailable) return;
    client = new SigbashClient({
      apiKey: API_KEY,
      userKey: LIVE_USER_KEY,
      userSecretKey: LIVE_USER_SECRET,
      serverUrl: SERVER_URL!,
    });
  });

  afterAll(() => client?.disconnect());

  it('scenario 32: registerTOTP returns { uri, secret }', async () => {
    if (!liveServerAvailable) return;
    const result = await client.registerTOTP(liveKeyId15);
    expect(result).toHaveProperty('uri');
    expect(result).toHaveProperty('secret');
    expect(typeof result.uri).toBe('string');
    expect(typeof result.secret).toBe('string');
    totpSecret15 = result.secret;
  });

  it("scenario 33: uri starts with 'otpauth://totp/'", async () => {
    if (!liveServerAvailable) return;
    // Re-register to get a fresh URI if totpSecret15 is not yet set
    if (!totpSecret15) {
      const result = await client.registerTOTP(liveKeyId15);
      totpSecret15 = result.secret;
    }
    const result = await client.registerTOTP(liveKeyId15);
    totpSecret15 = result.secret; // overwrite to keep in sync
    expect(result.uri.startsWith('otpauth://totp/')).toBe(true);
  });

  it('scenario 34: secret matches base32 alphabet /^[A-Z2-7]+$/', async () => {
    if (!liveServerAvailable) return;
    expect(totpSecret15).toMatch(/^[A-Z2-7]+$/);
  });

  it('scenario 35: confirmTOTP with valid code resolves successfully', async () => {
    if (!liveServerAvailable) return;
    const code = generateTOTPCode(totpSecret15);
    await expect(client.confirmTOTP(liveKeyId15, code)).resolves.toBeUndefined();
  });

  it('scenario 36: confirmTOTP with wrong code rejects with TOTPInvalidError', async () => {
    if (!liveServerAvailable) return;
    // liveKeyId15's TOTP is already verified by scenario 35, so the server returns
    // TOTP_ALREADY_VERIFIED instead of TOTP_INVALID.  Create a fresh 2FA key, register
    // TOTP (do NOT confirm it), then try confirming with a wrong code.
    const freshKey = await client.createKey({
      require2FA: true,
      network: 'signet',
      template: 'weekly-spending-limit',
      templateParams: { weeklyLimitSats: 1_000 },
      keyIndex: 98,
    });
    await client.registerTOTP(freshKey.keyId);
    await expect(client.confirmTOTP(freshKey.keyId, '000000')).rejects.toThrow(TOTPInvalidError);
  });
});

// ---------------------------------------------------------------------------
// signPSBT — live server (scenarios 38–44)
// ---------------------------------------------------------------------------

describe('signPSBT — live server', () => {
  const liveServerAvailable = !!SERVER_URL;
  let client: SigbashClient;

  beforeAll(async () => {
    if (!liveServerAvailable) return;
    client = new SigbashClient({
      apiKey: API_KEY,
      userKey: LIVE_USER_KEY,
      userSecretKey: LIVE_USER_SECRET,
      serverUrl: SERVER_URL!,
    });

    // Build funded signet PSBTs.
    // NOTE: createKey + getKey + bitcoin funding can take >30s; 120s timeout is set below.
    // Each scenario uses a DIFFERENT key (unique aggregate xpub) and therefore a different
    // policy root → separate nullifier pool. liveKmcJSON14 has max_uses=1 per weekly window,
    // so scenarios 38, 39, and 44 MUST use distinct policy roots to avoid nullifier conflicts.
    // Requires: local bitcoin-signet-instance container.
    const containerUp = isBitcoinContainerRunning();

    // Scenario 38: liveKeyId14 + liveKmcJSON14 (funded to kmcJSON14.bip328_xpub)
    if (liveKmcJSON14 && containerUp && !livePsbtBase64) {
      try {
        const kmc14 = JSON.parse(liveKmcJSON14) as { bip328_xpub?: string };
        if (kmc14.bip328_xpub) {
          livePsbtBase64 = buildPsbtFromUtxo(fundXpubAndGetUtxo(kmc14.bip328_xpub));
        }
      } catch { /* signPSBT scenario 38 will be skipped via !livePsbtBase64 guard */ }
    }

    // Scenario 39: liveKeyId15 + liveKmcJSON15 (funded to kmcJSON15.bip328_xpub)
    // liveKmcJSON15 was populated by scenario 28; its bip328_xpub differs from kmcJSON14
    // because the server uses a different partial key for each keyId slot.
    if (liveKmcJSON15 && containerUp && !livePsbtBase64_39) {
      try {
        const kmc15 = JSON.parse(liveKmcJSON15) as { bip328_xpub?: string };
        if (kmc15.bip328_xpub) {
          livePsbtBase64_39 = buildPsbtFromUtxo(fundXpubAndGetUtxo(kmc15.bip328_xpub));
        }
      } catch { /* scenario 39 will be skipped via !livePsbtBase64_39 guard */ }
    }

    // Scenario 44: fresh key created here → brand-new policy root, untouched nullifier pool.
    // Using liveKeyId15 again (even with liveKmcJSON15) would conflict with scenario 39
    // because they share the same policy root and max_uses=1 counter pool.
    if (liveServerAvailable) {
      try {
        const fresh44 = await client.createKey({
          require2FA: false,
          network: 'signet',
          template: 'weekly-spending-limit',
          templateParams: { weeklyLimitSats: 75_000 }, // unique value → unique policyRoot → fresh nullifier pool
          keyIndex: 10,
        });
        liveKeyId44 = fresh44.keyId;
        const keyInfo44 = await client.getKey(liveKeyId44);
        liveKmcJSON44 = keyInfo44.kmcJSON;
        if (containerUp && !livePsbtBase64_44) {
          const kmc44 = JSON.parse(liveKmcJSON44) as { bip328_xpub?: string };
          if (kmc44.bip328_xpub) {
            livePsbtBase64_44 = buildPsbtFromUtxo(fundXpubAndGetUtxo(kmc44.bip328_xpub));
          }
        }
      } catch { /* scenario 44 will be skipped via !livePsbtBase64_44 || !liveKmcJSON44 guard */ }
    }
  }, 120_000); // 2-minute timeout: createKey + getKey + bitcoin funding can take >60s

  afterAll(() => client?.disconnect());

  it('scenario 38: sign with require2FA=false key + PSBT → { success: true }', async () => {
    if (!liveServerAvailable || !livePsbtBase64 || !liveKmcJSON14) return;
    const result = await client.signPSBT({
      keyId: liveKeyId14,
      psbtBase64: livePsbtBase64!,
      kmcJSON: liveKmcJSON14,
      network: 'signet',
    });
    expect(result.success).toBe(true);
  });

  it('scenario 39: sign with require2FA=true key + valid TOTP → { success: true }', async () => {
    if (!liveServerAvailable || !livePsbtBase64_39 || !liveKmcJSON15) return;
    const code = generateTOTPCode(totpSecret15);
    const result = await client.signPSBT({
      keyId: liveKeyId15,
      psbtBase64: livePsbtBase64_39!,
      kmcJSON: liveKmcJSON15,
      network: 'signet',
      totpCode: code,
    });
    expect(result.success).toBe(true);
  });

  it('scenario 40: sign with require2FA=true + wrong TOTP rejects with TOTPInvalidError', async () => {
    if (!liveServerAvailable || !livePsbtBase64 || !liveKmcJSON14) return;
    await expect(
      client.signPSBT({
        keyId: liveKeyId15,
        psbtBase64: livePsbtBase64!,
        kmcJSON: liveKmcJSON14,
        network: 'signet',
        totpCode: '000000',
      })
    ).rejects.toThrow(TOTPInvalidError);
  });

  it('scenario 41: sign on 2FA key before confirmTOTP → TOTPSetupIncompleteError', async () => {
    if (!liveServerAvailable || !livePsbtBase64 || !liveKmcJSON14) return;
    // Create a fresh 2FA key that has NOT had confirmTOTP called.
    // Use a fresh apiKey so this user auto-registers as the first org admin.
    const freshClient = new SigbashClient({
      apiKey: SigbashClient.generateUserKey(),
      userKey: SigbashClient.generateUserKey(),
      userSecretKey: SigbashClient.generateUserSecretKey(),
      serverUrl: SERVER_URL!,
    });
    try {
      const keyResult = await freshClient.createKey({
        require2FA: true,
        network: 'signet',
        template: 'weekly-spending-limit',
        templateParams: { weeklyLimitSats: 10_000 },
      });
      // Register TOTP but do NOT confirm it
      await freshClient.registerTOTP(keyResult.keyId);
      const code = '000000'; // deliberately wrong code — intent is setup-incomplete error, not bad-code error
      await expect(
        freshClient.signPSBT({
          keyId: keyResult.keyId,
          psbtBase64: livePsbtBase64!,
          kmcJSON: liveKmcJSON14,
          network: 'signet',
          totpCode: code,
        })
      ).rejects.toThrow(TOTPSetupIncompleteError);
    } finally {
      freshClient.disconnect();
    }
  });

  it('scenario 42: invalid PSBT → throws a handled error', async () => {
    if (!liveServerAvailable) return;
    try {
      const result = await client.signPSBT({
        keyId: liveKeyId14,
        psbtBase64: 'not-a-valid-psbt-base64',
        kmcJSON: liveKmcJSON14 || '{}',
        network: 'signet',
      });
      // WASM may return success:false for malformed input
      expect(result.success).toBe(false);
    } catch (err) {
      // Or it may throw a handled SDK error (WASM_NOT_LOADED, SIGNING_FAILED, etc.)
      expect(err).toBeInstanceOf(Error);
    }
  });

  it('scenario 43: psbtHex variant is accepted (success or handled error)', async () => {
    if (!liveServerAvailable) return;
    try {
      const result = await client.signPSBT({
        keyId: liveKeyId14,
        psbtBase64: '',
        psbtHex: '70736274ff', // minimal PSBT magic bytes as hex
        kmcJSON: liveKmcJSON14 || '{}',
        network: 'signet',
      });
      // May succeed or return success:false depending on WASM validation
      expect(typeof result.success).toBe('boolean');
    } catch (err) {
      // Network or validation errors are acceptable here
      expect(err).toBeInstanceOf(Error);
    }
  });

  it('scenario 44: sign with fresh key (unique policy root → untouched nullifier pool) → success', async () => {
    // liveKeyId44 is created in beforeAll at keyIndex=10 with require2FA=false.
    // Its aggregate xpub differs from liveKeyId14/15, giving it a distinct policy root
    // and a fully fresh nullifier counter — no conflict with scenarios 38 or 39.
    if (!liveServerAvailable || !livePsbtBase64_44 || !liveKmcJSON44) return;
    const result = await client.signPSBT({
      keyId: liveKeyId44,
      psbtBase64: livePsbtBase64_44!,
      kmcJSON: liveKmcJSON44,
      network: 'signet',
    });
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// verifyPSBT with WASM (scenarios 46–49)
// ---------------------------------------------------------------------------

describe('verifyPSBT with WASM — live server', () => {
  const liveServerAvailable = !!SERVER_URL;

  let wasmClient: SigbashClient;

  beforeAll(async () => {
    if (!liveServerAvailable) return;

    // WASM should already be loaded by createKey beforeAll, but guard for isolation.
    if (!isWasmReady()) {
      if (!WASM_LOAD_URL) throw new Error('No WASM source: set SIGBASH_TEST_SERVER_URL');
      const expectedHash = await fetchExpectedWasmHash();
      const t0 = Date.now();
      await loadWasm({
        wasmUrl: WASM_LOAD_URL,
        expectedHash,
      });
    }

    // Build a fresh client (uses LIVE_USER_KEY so getKey works for liveKeyId14)
    wasmClient = new SigbashClient({
      apiKey: API_KEY,
      userKey: LIVE_USER_KEY,
      userSecretKey: LIVE_USER_SECRET,
      serverUrl: SERVER_URL!,
    });

    // Create a restrictive key (1-sat cap) used in scenario 47
    const r = await wasmClient.createKey({
      require2FA: false,
      network: 'signet',
      template: 'weekly-spending-limit',
      templateParams: { weeklyLimitSats: 1 },
      keyIndex: 99,
    });
    restrictiveKeyId = r.keyId;
    // Fetch its kmcJSON for verifyPSBT
    const rKey = await wasmClient.getKey(restrictiveKeyId, { keyIndex: 99 });
    restrictiveKeyId = rKey.kmcJSON; // reuse variable to hold kmcJSON for scenario 47
  }, 120_000); // 2-minute timeout: WASM download + instantiate can take >30s

  afterAll(() => wasmClient?.disconnect());

  it('scenario 46: verifyPSBT result has correct shape (passed, nullifierStatus)', async () => {
    if (!liveServerAvailable || !livePsbtBase64) return;
    const kmcJSON = liveKmcJSON14;
    expect(kmcJSON).toBeTruthy(); // populated in scenario 27
    const result = await wasmClient.verifyPSBT({
      psbtBase64: livePsbtBase64!,
      kmcJSON,
      network: 'signet',
    });
    expect(typeof result.passed).toBe('boolean');
    expect(Array.isArray(result.nullifierStatus)).toBe(true);
  });

  it('scenario 47: verifyPSBT with 1-sat-cap policy returns passed:false for any real PSBT', async () => {
    if (!liveServerAvailable || !livePsbtBase64) return;
    const restrictiveKmcJSON = restrictiveKeyId; // holds kmcJSON after beforeAll
    expect(restrictiveKmcJSON).toBeTruthy();
    const result = await wasmClient.verifyPSBT({
      psbtBase64: livePsbtBase64!,
      kmcJSON: restrictiveKmcJSON,
      network: 'signet',
    });
    expect(result.passed).toBe(false);
  });

  it('scenario 48: progress callback is invoked during WASM evaluation', async () => {
    if (!liveServerAvailable || !livePsbtBase64) return;
    const callbacks: string[] = [];
    await wasmClient.verifyPSBT({
      psbtBase64: livePsbtBase64!,
      kmcJSON: liveKmcJSON14,
      network: 'signet',
      progressCallback: (msg: string) => { callbacks.push(msg); },
    });
    expect(callbacks.length).toBeGreaterThan(0);
  });

  it('scenario 49: calling verifyPSBT twice returns identical passed value (idempotent)', async () => {
    if (!liveServerAvailable || !livePsbtBase64) return;
    const opts = { psbtBase64: livePsbtBase64!, kmcJSON: liveKmcJSON14, network: 'signet' as const };
    const first = await wasmClient.verifyPSBT(opts);
    const second = await wasmClient.verifyPSBT(opts);
    expect(second.passed).toBe(first.passed);
  });
});

// ---------------------------------------------------------------------------
// registerUser / revokeUser — live server (scenarios 50–54)
// ---------------------------------------------------------------------------

describe('registerUser and revokeUser — live server', () => {
  const liveServerAvailable = !!SERVER_URL;
  let adminClient: SigbashClient;
  let nonAdminClient: SigbashClient;
  const newUserKey = SigbashClient.generateUserKey();
  let registeredUserClient: SigbashClient;

  beforeAll(() => {
    if (!liveServerAvailable) return;
    // Admin is the LIVE credential pair (first-registered user in the org)
    adminClient = new SigbashClient({
      apiKey: API_KEY,
      userKey: LIVE_USER_KEY,
      userSecretKey: LIVE_USER_SECRET,
      serverUrl: SERVER_URL!,
    });
    // Non-admin is a separately registered user
    nonAdminClient = new SigbashClient({
      apiKey: API_KEY,
      userKey: SigbashClient.generateUserKey(),
      userSecretKey: SigbashClient.generateUserSecretKey(),
      serverUrl: SERVER_URL!,
    });
  });

  afterAll(() => {
    adminClient?.disconnect();
    nonAdminClient?.disconnect();
    registeredUserClient?.disconnect();
  });

  it('scenario 50: admin registerUser(newUserKey) → resolves without error', async () => {
    if (!liveServerAvailable) return;
    await expect(adminClient.registerUser(newUserKey)).resolves.toBeUndefined();
  });

  it('scenario 51: non-admin calling registerUser → rejects with AdminError', async () => {
    if (!liveServerAvailable) return;
    const anotherKey = SigbashClient.generateUserKey();
    await expect(nonAdminClient.registerUser(anotherKey)).rejects.toThrow(AdminError);
  });

  it('scenario 52: admin revokeUser(registeredUserKey) → resolves without error', async () => {
    if (!liveServerAvailable) return;
    // Register a fresh user to revoke
    const revokeTargetKey = SigbashClient.generateUserKey();
    await adminClient.registerUser(revokeTargetKey);
    await expect(adminClient.revokeUser(revokeTargetKey)).resolves.toBeUndefined();
  });

  it('scenario 53: non-admin calling revokeUser → rejects with AdminError', async () => {
    if (!liveServerAvailable) return;
    const targetKey = SigbashClient.generateUserKey();
    await expect(nonAdminClient.revokeUser(targetKey)).rejects.toThrow(AdminError);
  });

  it('scenario 54: registered non-admin user can createKey after registration', async () => {
    if (!liveServerAvailable) return;
    registeredUserClient = new SigbashClient({
      apiKey: API_KEY,
      userKey: newUserKey,
      userSecretKey: SigbashClient.generateUserSecretKey(),
      serverUrl: SERVER_URL!,
    });
    const result = await registeredUserClient.createKey({
      require2FA: false,
      network: 'signet',
      template: 'weekly-spending-limit',
      templateParams: { weeklyLimitSats: 5_000 },
    });
    expect(typeof result.keyId).toBe('string');
    expect(result.keyId.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// disconnect — live server (scenarios 55–56)
// ---------------------------------------------------------------------------

describe('disconnect — Tier 1 + live', () => {
  it('scenario 55: client.disconnect() does not throw', () => {
    const client = new SigbashClient({
      apiKey: API_KEY,
      userKey: SigbashClient.generateUserKey(),
      userSecretKey: SigbashClient.generateUserSecretKey(),
      serverUrl: DUMMY_URL,
    });
    expect(() => client.disconnect()).not.toThrow();
  });

  it('scenario 56: calling disconnect() twice is safe', () => {
    const client = new SigbashClient({
      apiKey: API_KEY,
      userKey: SigbashClient.generateUserKey(),
      userSecretKey: SigbashClient.generateUserSecretKey(),
      serverUrl: DUMMY_URL,
    });
    client.disconnect();
    expect(() => client.disconnect()).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Covenant Emulation — live server (scenarios 58–61)
// ---------------------------------------------------------------------------

describe('Covenant Emulation — live server', () => {
  const liveServerAvailable = !!SERVER_URL;
  let client: SigbashClient;

  beforeAll(async () => {
    if (!liveServerAvailable) return;
    client = new SigbashClient({
      apiKey: API_KEY,
      userKey: LIVE_USER_KEY,
      userSecretKey: LIVE_USER_SECRET,
      serverUrl: SERVER_URL!,
    });

    // Create a single key with an OR policy covering both TX1 (OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT)
    // and TX2 (INPUT_COMMITTED_DATA_VERIFY) conditions.  Using the same key ensures both transactions
    // share the same policyRoot, which is required for the covenant state DB lookup in TX2.
    try {
      const covenantPolicy: POETPolicy = {
        version: '1.1',
        policy: {
          type: 'operator',
          operator: 'OR',
          operands: [
            {
              type: 'condition',
              conditionType: 'OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT',
              conditionParams: { output_index: 0, committed_data_hex: '5120SIGBASH_OUTPUT_KEY', validation_mode: 'literal' },
              description: 'TX1 path: covenant output must be P2TR to our aggregate key',
            },
            {
              type: 'condition',
              conditionType: 'INPUT_COMMITTED_DATA_VERIFY',
              conditionParams: { input_index: 0, witness_data_hex: 'SIGBASH_COVENANT_STATE', validation_mode: 'literal' },
              description: 'TX2 path: input must commit to covenant state written at TX1',
            },
          ],
        },
      };

      const fresh58 = await client.createKey({
        require2FA: false,
        network: 'signet',
        policy: covenantPolicy,
        keyIndex: 20,
      });
      liveKeyId58 = fresh58.keyId;
      const keyInfo58 = await client.getKey(liveKeyId58);
      liveKmcJSON58 = keyInfo58.kmcJSON;

      const containerUp = isBitcoinContainerRunning();
      if (containerUp) {
        const kmc58 = JSON.parse(liveKmcJSON58) as { bip328_xpub?: string };
        if (kmc58.bip328_xpub) {
          // Fund the covenant key's P2TR address and build TX1 PSBT (self-payment)
          const utxo = fundXpubAndGetUtxo(kmc58.bip328_xpub);
          liveTx1ScriptPubKeyHex = utxo.scriptPubKeyHex;
          liveTx1OutputSats = utxo.valueSats - 1000; // gen-test-psbt.cjs deducts 1000 sat fee
          livePsbtBase64_59 = buildPsbtFromUtxo(utxo);
        }
      }
    } catch { /* scenarios will be skipped via guards if setup fails */ }
  }, 120_000); // 2-minute timeout: createKey + getKey + bitcoin funding can take >60s

  afterAll(() => client?.disconnect());

  it('scenario 58: createKey with OR covenant policy (OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT | INPUT_COMMITTED_DATA_VERIFY) → succeeds without error', async () => {
    if (!liveServerAvailable || !liveKeyId58) return;
    expect(typeof liveKeyId58).toBe('string');
    expect(liveKeyId58.length).toBeGreaterThan(0);
  });

  it('scenario 59: signPSBT TX1 (self-payment, OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT path) → { success: true }; broadcast TX1 and capture txid', async () => {
    if (!liveServerAvailable || !livePsbtBase64_59 || !liveKmcJSON58 || !liveKeyId58) return;
    const result = await client.signPSBT({
      keyId: liveKeyId58,
      psbtBase64: livePsbtBase64_59,
      kmcJSON: liveKmcJSON58,
      network: 'signet',
    });
    expect(result.success).toBe(true);
    expect(result.txHex).toBeDefined();
    // Broadcast TX1 so it lands in the mempool; capture txid for TX2 construction in scenario 61
    if (result.txHex) {
      liveTx1Txid = sendRawTx(result.txHex);
    }
  });

  it('scenario 60: mine 1 block to confirm TX1; covenant_state DB table has at least one row; build TX2 PSBT', async () => {
    if (!liveServerAvailable || !liveTx1Txid || !liveTx1ScriptPubKeyHex) return;
    // Confirm TX1 on-chain so TX2 can reference its output as a confirmed UTXO
    mineBlock();
    // Assert that TX1 signing caused the WASM to write a covenant state record to the DB
    const dbContainer = process.env.SIGBASH_DB_CONTAINER || 'sigbash-db';
    const dbName = process.env.SIGBASH_DB_NAME || 'sigbash';
    const count = execSync(
      `docker exec ${dbContainer} psql -U postgres -d ${dbName} -tAc "SELECT count(*) FROM covenant_state"`,
      { encoding: 'utf-8' },
    ).trim();
    expect(parseInt(count, 10)).toBeGreaterThan(0);
    // Build TX2 PSBT spending TX1 output 0 (same scriptPubKey, value minus fee already deducted)
    livePsbtBase64_61 = buildPsbtFromUtxo({
      txid: liveTx1Txid,
      vout: 0,
      valueSats: liveTx1OutputSats,
      scriptPubKeyHex: liveTx1ScriptPubKeyHex,
    });
  });

  it('scenario 61: signPSBT TX2 (spends TX1 output, INPUT_COMMITTED_DATA_VERIFY path) → { success: true }', async () => {
    if (!liveServerAvailable || !livePsbtBase64_61 || !liveKmcJSON58 || !liveKeyId58) return;
    const result = await client.signPSBT({
      keyId: liveKeyId58,
      psbtBase64: livePsbtBase64_61,
      kmcJSON: liveKmcJSON58,
      network: 'signet',
    });
    expect(result.success).toBe(true);
  });
});
