import express from 'express';
import { readFileSync } from 'fs';
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

// ── Constants ──────────────────────────────────────────────────────────────
const DEFAULT_SERVER_URL = 'https://www.sigbash.com';
const {
  SIGBASH_WASM_URL = `${DEFAULT_SERVER_URL}/sigbash.wasm`,
  PORT = '3000',
} = process.env;

// ── Credential resolution ──────────────────────────────────────────────────
// Priority per request: .env file → process.env → X-Sigbash-* headers
function parseDotEnv() {
  try {
    return Object.fromEntries(
      readFileSync('.env', 'utf8').split('\n')
        .map(l => l.match(/^([^#=]+)=(.*)$/))
        .filter(Boolean)
        .map(([, k, v]) => [k.trim(), v.trim()])
    );
  } catch {
    return {};
  }
}

function resolveCredentials(req) {
  const file = parseDotEnv();
  const get = (fileKey, envKey, header) =>
    file[fileKey] || process.env[envKey] || req.headers[header] || '';
  return {
    serverUrl:     file['SIGBASH_SERVER_URL'] || process.env.SIGBASH_SERVER_URL || req.headers['x-sigbash-server-url'] || DEFAULT_SERVER_URL,
    apiKey:        get('SIGBASH_API_KEY',    'SIGBASH_API_KEY',    'x-sigbash-api-key'),
    userKey:       get('SIGBASH_USER_KEY',   'SIGBASH_USER_KEY',   'x-sigbash-user-key'),
    userSecretKey: get('SIGBASH_SECRET_KEY', 'SIGBASH_SECRET_KEY', 'x-sigbash-secret-key'),
  };
}

// ── Per-request credential middleware ──────────────────────────────────────
// /health and /setup/credentials are exempt — all other routes require creds.
const EXEMPT = new Set(['/health', '/setup/credentials']);

function requireCredentials(req, res, next) {
  if (EXEMPT.has(req.path)) return next();
  const { apiKey, userKey, userSecretKey } = resolveCredentials(req);
  if (!apiKey || !userKey || !userSecretKey) {
    return res.status(401).json({
      error: 'Missing credentials. Provide SIGBASH_API_KEY, SIGBASH_USER_KEY, and SIGBASH_SECRET_KEY via .env, environment variables, or X-Sigbash-* headers.',
    });
  }
  next();
}

// ── Client factory ─────────────────────────────────────────────────────────
function client(req) {
  const { serverUrl, apiKey, userKey, userSecretKey } = resolveCredentials(req);
  return new SigbashClient({ serverUrl, apiKey, userKey, userSecretKey });
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
app.use(requireCredentials);

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ── Setup utilities (credential bootstrap) ─────────────────────────────────

// Generate a fresh credential triplet. Call this before you have credentials.
// Does not write any file — copy the response into your .env.
app.post('/setup/credentials', (_req, res) => {
  const randomHex = () => Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  res.json({
    apiKey:        randomHex(),
    userKey:       randomHex(),
    userSecretKey: randomHex(),
    serverUrl:     DEFAULT_SERVER_URL,
  });
});

// Return the hashes Sigbash knows for the currently configured credentials.
// Share apikeyHash with Sigbash to identify your org (e.g. to request mainnet access).
app.get('/setup/auth-hash', async (req, res) => {
  try {
    const { apiKey, userKey } = resolveCredentials(req);
    const hashes = await getAuthHash(apiKey, userKey);
    res.json({ ...hashes, note: 'Share apikeyHash with Sigbash to identify your org (e.g. to request mainnet access).' });
  } catch (err) { handleError(err, res); }
});

app.post('/keys', async (req, res) => {
  try { res.json(await client(req).createKey(req.body)); }
  catch (err) { handleError(err, res); }
});

app.get('/keys/:keyId', async (req, res) => {
  try {
    const verbose = req.query.verbose === 'true';
    res.json(await client(req).getKey(req.params.keyId, { verbose }));
  }
  catch (err) { handleError(err, res); }
});

app.post('/keys/:keyId/sign', async (req, res) => {
  try { res.json(await client(req).signPSBT({ keyId: req.params.keyId, ...req.body })); }
  catch (err) { handleError(err, res); }
});

app.post('/keys/:keyId/verify', async (req, res) => {
  try { res.json(await client(req).verifyPSBT(req.body)); }
  catch (err) { handleError(err, res); }
});

app.post('/keys/:keyId/totp/register', async (req, res) => {
  try { res.json(await client(req).registerTOTP(req.params.keyId)); }
  catch (err) { handleError(err, res); }
});

app.post('/keys/:keyId/totp/confirm', async (req, res) => {
  try { await client(req).confirmTOTP(req.params.keyId, req.body.totpCode); res.json({ ok: true }); }
  catch (err) { handleError(err, res); }
});

app.get('/keys/:keyId/recovery-kit', async (req, res) => {
  try { res.json(await client(req).exportRecoveryKit(req.params.keyId, req.query)); }
  catch (err) { handleError(err, res); }
});

app.post('/recovery', async (req, res) => {
  try { res.json(await client(req).recoverFromKit(req.body)); }
  catch (err) { handleError(err, res); }
});

app.post('/admin/recover', async (req, res) => {
  try {
    const { targetUserKey, keyId, recoveryKit } = req.body;
    res.json(await client(req).adminRecoverKey(targetUserKey, keyId, recoveryKit));
  }
  catch (err) { handleError(err, res); }
});

app.post('/admin/users', async (req, res) => {
  try { await client(req).registerUser(req.body.userKey); res.json({ ok: true }); }
  catch (err) { handleError(err, res); }
});

app.delete('/admin/users/:userKey', async (req, res) => {
  try { await client(req).revokeUser(req.params.userKey); res.json({ ok: true }); }
  catch (err) { handleError(err, res); }
});

// ── Startup ────────────────────────────────────────────────────────────────
async function start() {
  const versionUrl = new URL('wasm-version.json', SIGBASH_WASM_URL).href;
  const versionRes = await fetch(versionUrl);
  if (!versionRes.ok) throw new Error(`Failed to fetch ${versionUrl}: ${versionRes.status}`);
  const { sha384 } = await versionRes.json();
  // wasm-version.json stores sha384 as base64; loadWasm expects hex
  const expectedHash = Buffer.from(sha384, 'base64').toString('hex');

  console.log(`Loading WASM from ${SIGBASH_WASM_URL} ...`);
  await loadWasm({ wasmUrl: SIGBASH_WASM_URL, expectedHash });
  console.log('WASM ready.');

  const server = app.listen(parseInt(PORT), () =>
    console.log(`sigbash-http-server listening on :${PORT}`)
  );
  // signPSBT involves ZK proof generation and can be long-running.
  server.setTimeout(0);
}

start().catch(err => { console.error(err); process.exit(1); });
