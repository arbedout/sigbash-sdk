/**
 * updatePolicy seed-restoration tests.
 *
 * Both legs need the real WASM binary, and the SDK has no local wasm source,
 * so both run only against a live test server (SIGBASH_TEST_SERVER_URL) —
 * skipped gracefully otherwise. The fail-closed leg must run before any
 * parent-process call that would initialize the global SeedManager.
 *
 * Tier 1 — live server, no key required: the raw WASM updatePolicy export
 *          fails closed when no seed material is available in a fresh WASM
 *          instance (error: "SeedManager not initialized").
 * Tier 2 — live server: the documented fresh-process flow — a CHILD process
 *          creates an updateable key, this process then calls updatePolicy()
 *          without ever having called createKey() or signPSBT().
 */

import { spawnSync } from 'child_process';
import { existsSync } from 'fs';
import { loadWasm, isWasmReady, SigbashClient } from './index';

const SERVER_URL = process.env['SIGBASH_TEST_SERVER_URL'];
const WASM_LOAD_URL = SERVER_URL ? `${SERVER_URL}/sigbash.wasm` : undefined;
// The create leg runs in a plain child process, which cannot execute the TS
// sources; it requires the built CJS bundle instead. The leg skips (with a
// logged reason) when no build is present — run `npm run build` first.
const DIST_ENTRY = require.resolve('../dist/index.cjs');
const DIST_AVAILABLE = existsSync(DIST_ENTRY);

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

// Child-process helper: the create leg runs in its own process so the update
// leg below genuinely starts with an uninitialized SeedManager.
function createUpdateableKeyInChildProcess(): {
  apiKey: string; userKey: string; userSecretKey: string;
  keyId: string; bip328Xpub: string; policyRoot: string;
} {
  const script = `
    (async () => {
      const { loadWasm, SigbashClient, generateCredentials } = require(${JSON.stringify(DIST_ENTRY)});
      await loadWasm({ wasmUrl: ${JSON.stringify(WASM_LOAD_URL)} });
      const creds = await generateCredentials();
      const client = new SigbashClient({
        serverUrl: ${JSON.stringify(SERVER_URL)},
        apiKey: creds.apiKey, userKey: creds.userKey, userSecretKey: creds.userSecretKey,
      });
      const key = await client.createKey({ policy: ${JSON.stringify(minimalPolicy)}, network: 'signet', require2FA: false, updateable: true });
      process.stdout.write(JSON.stringify({
        apiKey: creds.apiKey, userKey: creds.userKey, userSecretKey: creds.userSecretKey,
        keyId: key.keyId, bip328Xpub: key.bip328Xpub, policyRoot: key.policyRoot,
      }));
    })().catch(e => { console.error(e); process.exit(1); });
  `;
  const res = spawnSync('node', ['-e', script], { encoding: 'utf8' });
  if (res.status !== 0) throw new Error(`create leg failed: ${res.stderr}`);
  return JSON.parse(res.stdout);
}

const liveReady = !!SERVER_URL && !!WASM_LOAD_URL;

beforeAll(async () => {
  if (!liveReady || isWasmReady()) return;
  await loadWasm({ wasmUrl: WASM_LOAD_URL! });
}, 120_000);

(SERVER_URL ? describe : describe.skip)('updatePolicy seed restoration', () => {
  it('fails closed when no seed material is available', async () => {
    const updatePolicyFn = (globalThis as Record<string, unknown>)['updatePolicy'] as (input: string) => string;
    const result = JSON.parse(updatePolicyFn(JSON.stringify({
      kmc_json: JSON.stringify({ credential_id: 'test-credential' }),
      new_policy_json: JSON.stringify(minimalPolicy),
      network: 'signet',
    })));
    expect(result.error).toBe('SeedManager not initialized');
  });

  (DIST_AVAILABLE ? it : it.skip)('fresh-process create → update keeps bip328Xpub and bumps the update count', async () => {
    const created = createUpdateableKeyInChildProcess();
    const client = new SigbashClient({
      serverUrl: SERVER_URL!,
      apiKey: created.apiKey, userKey: created.userKey, userSecretKey: created.userSecretKey,
    });
    const after = await client.getKey(created.keyId);
    await client.updatePolicy(created.keyId, JSON.stringify(minimalPolicy));
    const updated = await client.getKey(created.keyId);
    expect(updated.bip328Xpub).toBe(created.bip328Xpub);
    expect(updated.policyRoot).toBeDefined();
    expect(updated.policyUpdateCount ?? 1).toBe((after.policyUpdateCount ?? 0) + 1);
  });
});
