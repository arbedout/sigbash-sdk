import express from 'express';
import { readFileSync } from 'fs';
import crypto from 'crypto';
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
  // Binds loopback-only by default — this server holds live credentials and
  // will sign/spend on behalf of whoever can reach it. Set explicitly (e.g.
  // to 0.0.0.0 inside a container, or behind a reverse proxy that terminates
  // its own auth) only when the listener token below is also in place.
  SIGBASH_BIND_HOST = '127.0.0.1',
  SIGBASH_LISTENER_TOKEN,
} = process.env;

// ── Listener auth ────────────────────────────────────────────────────────
// Independent of the X-Sigbash-* credential-supply headers (which carry the
// *caller's own* Sigbash credentials for the multi-tenant header path and are
// validated upstream by sigbash.com). This token instead gates access to the
// local HTTP listener itself: without it, once an operator configures
// .env/env-var credentials, any network peer that can reach the port would
// otherwise be able to sign/read/export recovery kits using those
// credentials with no proof of authorization at all.
const LISTENER_TOKEN = SIGBASH_LISTENER_TOKEN || crypto.randomBytes(32).toString('hex');
if (!SIGBASH_LISTENER_TOKEN) {
  console.error(`Generated listener token (pass as 'Authorization: Bearer <token>'): ${LISTENER_TOKEN}`);
  console.error('Set SIGBASH_LISTENER_TOKEN to use a fixed token across restarts.');
}

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

function requireListenerToken(req, res, next) {
  if (EXEMPT.has(req.path)) return next();
  const header = req.headers['authorization'] || '';
  const [scheme, token] = header.split(' ');
  const tokenBuf = Buffer.from(token || '');
  const expectedBuf = Buffer.from(LISTENER_TOKEN);
  const valid = scheme === 'Bearer' &&
    tokenBuf.length === expectedBuf.length &&
    crypto.timingSafeEqual(tokenBuf, expectedBuf);
  if (!valid) {
    return res.status(401).json({ error: 'Missing or invalid Authorization: Bearer <listener token>.' });
  }
  next();
}

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
// PoP request signing is handled transparently inside SigbashClient —
// it derives the Ed25519 PoP key from userSecretKey at construction and signs
// every REST request / Socket.IO event. No passthrough required here.
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
app.use(requireListenerToken);
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

app.get('/keys', async (req, res) => {
  try { res.json(await client(req).listKeys()); }
  catch (err) { handleError(err, res); }
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

app.post('/keys/:keyId/update-policy', async (req, res) => {
  try {
    const { newPolicyJson } = req.body;
    res.json(await client(req).updatePolicy(req.params.keyId, newPolicyJson));
  }
  catch (err) { handleError(err, res); }
});

app.post('/admin/users', async (req, res) => {
  try {
    const { userKey, newUserPopPubkey } = req.body || {};
    if (!newUserPopPubkey) {
      return res.status(400).json({
        error: 'newUserPopPubkey is required (64-char hex Ed25519 public key derived from new user\'s userSecretKey)',
      });
    }
    await client(req).registerUser(userKey, newUserPopPubkey);
    res.json({ ok: true });
  }
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

  const server = app.listen(parseInt(PORT), SIGBASH_BIND_HOST, () =>
    console.log(`sigbash-http-server listening on ${SIGBASH_BIND_HOST}:${PORT}`)
  );
  // signPSBT involves ZK proof generation and can be long-running.
  server.setTimeout(0);
}

start().catch(err => { console.error(err); process.exit(1); });
