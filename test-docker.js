#!/usr/bin/env node
'use strict';

const { execSync } = require('child_process');
const path = require('path');

// ── Config ─────────────────────────────────────────────────────────────────
const IMAGE     = 'sigbash-server-test';
const CONTAINER = 'sigbash-server-test';
const PORT      = 3099;
const BASE      = `http://localhost:${PORT}`;
const SIGNET    = 'bitcoin-signet-instance';
const MASTER    = 'testing_master';
const GEN_PSBT  = path.resolve(__dirname, 'src/__tests__/helpers/gen-test-psbt.cjs');

const ENV_KEYS  = ['SIGBASH_SERVER_URL', 'SIGBASH_API_KEY', 'SIGBASH_USER_KEY', 'SIGBASH_SECRET_KEY'];

// ── Helpers ─────────────────────────────────────────────────────────────────
const run  = (cmd, opts = {}) => execSync(cmd, { encoding: 'utf8', stdio: 'pipe', ...opts }).trim();
const btc  = (cmd, w) => run(`docker exec ${SIGNET} bitcoin-cli -signet${w ? ` -rpcwallet=${w}` : ''} ${cmd}`);
const btcj = (cmd, w) => JSON.parse(btc(cmd, w));

async function api(method, p, body) {
  const res = await fetch(`${BASE}${p}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`${method} ${p} → ${res.status}: ${JSON.stringify(data)}`);
  return data;
}

async function waitReady(ms = 120_000) {
  const t = Date.now();
  while (Date.now() - t < ms) {
    try { if ((await fetch(`${BASE}/health`)).ok) return; } catch {}
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error('Server did not become ready (WASM load timeout?)');
}

function fundAndBuildPsbt(bip328Xpub) {
  const esc    = s => s.replace(/'/g, "'\\''");
  const desc   = btcj(`getdescriptorinfo '${esc(`tr(${bip328Xpub}/*))`)}'`).descriptor;
  const addr   = btcj(`deriveaddresses '${esc(desc)}' '[0,0]'`)[0];
  const spk    = btcj(`getaddressinfo ${addr}`, MASTER).scriptPubKey;
  const txid   = btc(`sendtoaddress ${addr} 0.00002`, MASTER);
  btc(`generatetoaddress 1 ${btc(`getnewaddress "mine" "bech32m"`, MASTER)}`);
  const out    = btcj(`getrawtransaction ${txid} true`).vout.find(o => o.scriptPubKey.hex === spk);
  if (!out) throw new Error('Could not locate funded output in raw tx');
  return run(`node "${GEN_PSBT}" "${txid}" "${out.n}" "${Math.round(out.value * 1e8)}" "${spk}"`);
}

// ── Main ────────────────────────────────────────────────────────────────────
async function main() {
  for (const k of ENV_KEYS) {
    if (!process.env[k]) throw new Error(`Missing required env var: ${k}`);
  }

  console.log('Building Docker image...');
  run(`docker build -t ${IMAGE} .`, { cwd: __dirname, stdio: 'inherit' });

  const envFlags = ENV_KEYS.map(k => `-e "${k}=${process.env[k]}"`).join(' ');
  run(`docker run -d --name ${CONTAINER} -p ${PORT}:3000 ${envFlags} ${IMAGE}`);

  try {
    process.stdout.write('Waiting for server (WASM fetch + init)...');
    await waitReady();
    console.log(' ready.\n');

    // 1. createKey
    process.stdout.write('1/5  createKey ... ');
    const { keyId, p2trAddress } = await api('POST', '/keys', {
      template: 'weekly-spending-limit',
      templateParams: { weeklyLimitSats: 100_000 },
      network: 'signet',
      require2FA: false,
    });
    console.log(`keyId=${keyId}  addr=${p2trAddress}`);

    // 2. getKey
    process.stdout.write('2/5  getKey ... ');
    const got  = await api('GET', `/keys/${keyId}`);
    const kmc  = JSON.parse(got.kmcJSON);
    if (!kmc.bip328_xpub) throw new Error('No bip328_xpub in returned KMC');
    console.log('ok');

    // 3. fund → sign → broadcast
    process.stdout.write('3/5  fund + signPSBT ... ');
    const psbtBase64 = fundAndBuildPsbt(kmc.bip328_xpub);
    const signed = await api('POST', `/keys/${keyId}/sign`, { psbtBase64, kmcJSON: got.kmcJSON, network: 'signet' });
    if (!signed.success) throw new Error(`Signing failed: ${signed.error}`);
    btc(`sendrawtransaction ${signed.txHex}`);
    console.log(`ok  satisfiedClause=${signed.satisfiedClause}`);

    // 4. exportRecoveryKit
    process.stdout.write('4/5  exportRecoveryKit ... ');
    const kit = await api('GET', `/keys/${keyId}/recovery-kit`);
    if (kit.version !== 'sdk-recovery-v1') throw new Error(`Unexpected kit version: ${kit.version}`);
    console.log('ok');

    // 5. recoverFromKit → verify KMC roundtrip
    process.stdout.write('5/5  recoverFromKit ... ');
    const recovered = await api('POST', '/recovery', kit);
    if (recovered.kmcJSON !== got.kmcJSON) throw new Error('Recovered KMC does not match original');
    console.log('ok');

    console.log('\n✓ All tests passed.');
  } finally {
    run(`docker rm -f ${CONTAINER}`);
    console.log('Container torn down.');
  }
}

main().catch(err => { console.error('\n✗ FAIL:', err.message); process.exit(1); });
