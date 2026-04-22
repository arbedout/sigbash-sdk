import express from 'express';
import {
  loadWasm,
  SigbashClient,
  SigbashSDKError,
  PolicyCompileError,
  KeyIndexExistsError,
  TOTPRequiredError,
  TOTPInvalidError,
  AdminError,
  NetworkError,
  getAuthHash,
} from '@sigbash/sdk';

// ── Environment ────────────────────────────────────────────────────────────
const {
  SIGBASH_SERVER_URL,
  SIGBASH_API_KEY,
  SIGBASH_USER_KEY,
  SIGBASH_SECRET_KEY,
  SIGBASH_WASM_URL = 'https://www.sigbash.com/sigbash.wasm',
  PORT = '3000',
} = process.env;

for (const [k, v] of Object.entries({ SIGBASH_SERVER_URL, SIGBASH_API_KEY, SIGBASH_USER_KEY, SIGBASH_SECRET_KEY })) {
  if (!v) { console.error(`Missing required environment variable: ${k}`); process.exit(1); }
}

// ── Client factory ─────────────────────────────────────────────────────────
// SigbashClient is lightweight; socket connects lazily per operation.
function client() {
  return new SigbashClient({
    serverUrl:     SIGBASH_SERVER_URL,
    apiKey:        SIGBASH_API_KEY,
    userKey:       SIGBASH_USER_KEY,
    userSecretKey: SIGBASH_SECRET_KEY,
  });
}

// ── Error mapping ──────────────────────────────────────────────────────────
function handleError(err, res) {
  if (err instanceof PolicyCompileError)
    return res.status(422).json({ error: err.message, compilationTrace: err.compilationTrace });
  if (err instanceof KeyIndexExistsError)
    return res.status(409).json({ error: err.message, nextAvailableIndex: err.nextAvailableIndex });
  if (err instanceof TOTPRequiredError || err instanceof TOTPInvalidError)
    return res.status(401).json({ error: err.message });
  if (err instanceof AdminError)
    return res.status(403).json({ error: err.message });
  if (err instanceof NetworkError || err instanceof SigbashSDKError)
    return res.status(400).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
}

// ── Routes ─────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ── Setup utilities (credential bootstrap) ─────────────────────────────────

// Generate a fresh credential triplet. Call this once before you have credentials;
// copy the response into your .env. Does not write any file (server is stateless).
app.post('/setup/credentials', (_req, res) => {
  const randomHex = () => Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  res.json({
    apiKey:        randomHex(),
    userKey:       randomHex(),
    userSecretKey: randomHex(),
    serverUrl:     SIGBASH_SERVER_URL,
  });
});

// Return the hashes Sigbash knows for the currently configured credentials.
// Share apikeyHash with Sigbash to identify your org (e.g. to request mainnet access).
app.get('/setup/auth-hash', async (_req, res) => {
  try {
    const hashes = await getAuthHash(SIGBASH_API_KEY, SIGBASH_USER_KEY);
    res.json({ ...hashes, note: 'Share apikeyHash with Sigbash to identify your org (e.g. to request mainnet access).' });
  } catch (err) { handleError(err, res); }
});

app.post('/keys', async (req, res) => {
  try { res.json(await client().createKey(req.body)); }
  catch (err) { handleError(err, res); }
});

app.get('/keys/:keyId', async (req, res) => {
  try { res.json(await client().getKey(req.params.keyId, req.query)); }
  catch (err) { handleError(err, res); }
});

app.post('/keys/:keyId/sign', async (req, res) => {
  try { res.json(await client().signPSBT({ keyId: req.params.keyId, ...req.body })); }
  catch (err) { handleError(err, res); }
});

app.post('/keys/:keyId/verify', async (req, res) => {
  try { res.json(await client().verifyPSBT(req.body)); }
  catch (err) { handleError(err, res); }
});

app.post('/keys/:keyId/totp/register', async (req, res) => {
  try { res.json(await client().registerTOTP(req.params.keyId)); }
  catch (err) { handleError(err, res); }
});

app.post('/keys/:keyId/totp/confirm', async (req, res) => {
  try { await client().confirmTOTP(req.params.keyId, req.body.totpCode); res.json({ ok: true }); }
  catch (err) { handleError(err, res); }
});

app.get('/keys/:keyId/recovery-kit', async (req, res) => {
  try { res.json(await client().exportRecoveryKit(req.params.keyId, req.query)); }
  catch (err) { handleError(err, res); }
});

app.post('/recovery', async (req, res) => {
  try { res.json(await client().recoverFromKit(req.body)); }
  catch (err) { handleError(err, res); }
});

app.post('/admin/recover', async (req, res) => {
  try {
    const { targetUserKey, keyId, recoveryKit } = req.body;
    res.json(await client().adminRecoverKey(targetUserKey, keyId, recoveryKit));
  }
  catch (err) { handleError(err, res); }
});

app.post('/admin/users', async (req, res) => {
  try { await client().registerUser(req.body.userKey); res.json({ ok: true }); }
  catch (err) { handleError(err, res); }
});

app.delete('/admin/users/:userKey', async (req, res) => {
  try { await client().revokeUser(req.params.userKey); res.json({ ok: true }); }
  catch (err) { handleError(err, res); }
});

// ── Startup ────────────────────────────────────────────────────────────────
async function start() {
  // Derive wasm-version.json URL from WASM URL to get integrity hash.
  // e.g. https://www.sigbash.com/sigbash.wasm → https://www.sigbash.com/wasm-version.json
  const versionUrl = new URL('wasm-version.json', SIGBASH_WASM_URL).href;
  const versionRes = await fetch(versionUrl);
  if (!versionRes.ok) throw new Error(`Failed to fetch ${versionUrl}: ${versionRes.status}`);
  const { sha384 } = await versionRes.json();

  console.log(`Loading WASM from ${SIGBASH_WASM_URL} ...`);
  await loadWasm({ wasmUrl: SIGBASH_WASM_URL, expectedHash: sha384 });
  console.log('WASM ready.');

  const server = app.listen(parseInt(PORT), () =>
    console.log(`sigbash-http-server listening on :${PORT}`)
  );
  // signPSBT involves ZK proof generation and can be long-running.
  server.setTimeout(0);
}

start().catch(err => { console.error(err); process.exit(1); });
