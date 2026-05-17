/**
 * Ed25519 Proof-of-Possession (PoP) request signing — T125.
 *
 * Every authenticated REST request carries an X-Sigbash-Sig header; every
 * authenticated Socket.IO event carries an `_sigbash_sig` payload field. An
 * exfiltrated `authHash` (from logs, proxies, header captures) is not by
 * itself sufficient to authenticate — the attacker also needs the Ed25519
 * private key derived from `userSecretKey`.
 *
 * Header / payload format:
 *
 *     t=<unix-ms>;n=<32-hex>;v=1;k=<8-hex-pubkey-prefix>;s=<128-hex-sig>
 *
 * Signed transcript:
 *
 *     SIGBASH-POP-V1
 *     <METHOD>
 *     <path-with-canonical-query>
 *     <sha256-hex of body bytes>
 *     <t>
 *     <n>
 *     <auth_hash>
 *
 * For Socket.IO events the body digest is sha256(canonical_json(payload
 * without `_sigbash_sig`)); method is "WS" and path is
 * "<namespace>#<event_name>". Handshake uses method "WS-CONNECT" and path
 * "<namespace>".
 */

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';

// noble/ed25519 v2's async API (`getPublicKeyAsync`, `signAsync`) uses
// WebCrypto's SHA-512 internally and does not require a hash injection.

const POP_DERIVE_INFO = new TextEncoder().encode('sigbash/sdk-pop-ed25519/v1');

const HEX_ALPHABET = '0123456789abcdef';

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    out += HEX_ALPHABET[(b >>> 4) & 0xf] + HEX_ALPHABET[b & 0xf];
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('hex string has odd length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export interface PopKey {
  /** 32-byte ed25519 private seed (HMAC-derived from userSecretKey). */
  readonly seed: Uint8Array;
  /** Hex-encoded 32-byte private seed. */
  readonly seedHex: string;
  /** 32-byte ed25519 public key. */
  readonly publicKey: Uint8Array;
  /** Hex-encoded public key (lowercase, 64 chars). */
  readonly publicKeyHex: string;
}

/**
 * Derive the PoP keypair deterministically from `userSecretKey`.
 *
 * popSeed = HMAC-SHA256(userSecretKey, "sigbash/sdk-pop-ed25519/v1")[:32]
 *
 * `userSecretKey` must be a hex string (64 chars) — the same value the SDK
 * passes via `SIGBASH_SECRET_KEY`.
 */
export async function derivePopKey(userSecretKey: string): Promise<PopKey> {
  if (!userSecretKey || typeof userSecretKey !== 'string') {
    throw new Error('derivePopKey: userSecretKey is required');
  }
  // userSecretKey is a 64-char hex string in normal flows; accept arbitrary
  // string input as well so this works with non-hex-encoded secrets.
  let secretBytes: Uint8Array;
  if (/^[0-9a-fA-F]{64}$/.test(userSecretKey)) {
    secretBytes = hexToBytes(userSecretKey.toLowerCase());
  } else {
    secretBytes = utf8(userSecretKey);
  }

  const seed = hmac(sha256, secretBytes, POP_DERIVE_INFO).slice(0, 32);
  return popKeyFromSeed(seed);
}

/**
 * Construct a PopKey from a raw 32-byte seed (or 64-char hex string).
 * Used by recoverFromKit() to re-establish PoP authentication for a client
 * whose `userSecretKey` is no longer the one that originally produced the
 * registered `pop_pubkey`.
 */
export async function popKeyFromSeed(seed: Uint8Array | string): Promise<PopKey> {
  const seedBytes = typeof seed === 'string' ? hexToBytes(seed.toLowerCase()) : seed;
  if (seedBytes.length !== 32) {
    throw new Error('popKeyFromSeed: seed must be 32 bytes');
  }
  const publicKey = await ed.getPublicKeyAsync(seedBytes);
  return {
    seed: seedBytes,
    seedHex: bytesToHex(seedBytes),
    publicKey,
    publicKeyHex: bytesToHex(publicKey),
  };
}

/**
 * Deterministic JSON serialiser used to build the body digest for
 * Socket.IO event payloads. Objects have their keys sorted recursively;
 * arrays preserve order. Matches Python's
 * `json.dumps(value, sort_keys=True, separators=(',', ':'))`.
 */
export function canonicalJSON(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonicalJSON: non-finite number');
    return Number.isInteger(value) ? value.toFixed(0) : JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJSON).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
  }
  if (typeof value === 'undefined') return 'null';
  throw new Error(`canonicalJSON: unsupported type ${typeof value}`);
}

/**
 * Canonicalise a URL path + query string. Pairs are sorted lexically by
 * (key, value) and re-encoded — matches Python `urlencode(sorted(...))`.
 *
 * Input examples:
 *   "/foo"                  → "/foo"
 *   "/foo?b=2&a=1"          → "/foo?a=1&b=2"
 *   "https://x/foo?a=1"     → "/foo?a=1"   (origin stripped for relative-form)
 */
export function canonicalPath(rawPathOrUrl: string): string {
  // Accept absolute URLs by extracting pathname + search.
  let path = rawPathOrUrl;
  try {
    if (/^https?:\/\//i.test(rawPathOrUrl)) {
      const u = new URL(rawPathOrUrl);
      path = u.pathname + u.search;
    }
  } catch {
    // Fall back to raw string.
  }

  const qIdx = path.indexOf('?');
  if (qIdx < 0) return path;
  const base = path.substring(0, qIdx);
  const query = path.substring(qIdx + 1);
  if (!query) return base;

  // Parse pairs preserving repeated keys, then sort.
  const pairs: Array<[string, string]> = [];
  for (const chunk of query.split('&')) {
    if (!chunk) continue;
    const eq = chunk.indexOf('=');
    const k = eq < 0 ? chunk : chunk.substring(0, eq);
    const v = eq < 0 ? '' : chunk.substring(eq + 1);
    pairs.push([decodeURIComponent(k), decodeURIComponent(v)]);
  }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  const canonicalQs = pairs
    .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v))
    .join('&');
  return canonicalQs ? `${base}?${canonicalQs}` : base;
}

function generateNonce(): string {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return bytesToHex(buf);
}

export interface SignRequestInput {
  method: string;             // REST verb or "WS" / "WS-CONNECT"
  path: string;               // path with query (will be canonicalised)
  bodyBytes: Uint8Array;      // raw request body, or canonical-json bytes for sockets
  authHash: string;           // 64-hex DSHA256(apiKey||userKey)
  popKey: PopKey;
}

export interface SignedHeader {
  /** Header value to set as X-Sigbash-Sig (or place in `_sigbash_sig`). */
  value: string;
  /** Millisecond timestamp embedded in the signature. */
  t: number;
  /** 32-hex nonce embedded in the signature. */
  n: string;
}

/**
 * Build the canonical transcript bytes for a request.
 */
function buildTranscript(
  method: string,
  canonicalPathStr: string,
  bodySha256Hex: string,
  t: number,
  n: string,
  authHash: string,
): Uint8Array {
  const text =
    'SIGBASH-POP-V1\n' +
    method.toUpperCase() + '\n' +
    canonicalPathStr + '\n' +
    bodySha256Hex + '\n' +
    String(t) + '\n' +
    n + '\n' +
    authHash;
  return utf8(text);
}

/**
 * Sign a REST request. Caller is responsible for sending the returned
 * header value as `X-Sigbash-Sig` on the actual HTTP call.
 */
export async function signRequest(input: SignRequestInput): Promise<SignedHeader> {
  const t = Date.now();
  const n = generateNonce();
  const bodyDigest = bytesToHex(sha256(input.bodyBytes));
  const path = canonicalPath(input.path);
  const transcript = buildTranscript(input.method, path, bodyDigest, t, n, input.authHash);
  const sig = await ed.signAsync(transcript, input.popKey.seed);
  const k = input.popKey.publicKeyHex.slice(0, 8);
  const value = `t=${t};n=${n};v=1;k=${k};s=${bytesToHex(sig)}`;
  return { value, t, n };
}

/**
 * Sign a Socket.IO event or handshake auth payload. The returned header
 * value should be attached as `_sigbash_sig` on the outgoing payload.
 *
 * @param namespace - Socket.IO namespace (e.g. "/api/v2/sdk")
 * @param eventName - Empty string for handshake; event name for an event.
 * @param payload   - The event payload object. Will NOT be mutated; the
 *                    `_sigbash_sig` field (if any) is stripped before hashing.
 */
export async function signSocketPayload(
  namespace: string,
  eventName: string,
  payload: Record<string, unknown>,
  authHash: string,
  popKey: PopKey,
): Promise<SignedHeader> {
  const isHandshake = eventName === '';
  const method = isHandshake ? 'WS-CONNECT' : 'WS';
  const path = isHandshake ? namespace : `${namespace}#${eventName}`;

  // Strip our own field before hashing, in case caller passed the previous
  // payload back in. canonicalJSON sorts keys, so the order callers used is
  // irrelevant.
  const sanitised: Record<string, unknown> = {};
  for (const k of Object.keys(payload || {})) {
    if (k === '_sigbash_sig') continue;
    sanitised[k] = payload[k];
  }
  const canonical = canonicalJSON(sanitised);
  const bodyBytes = utf8(canonical);
  return signRequest({
    method,
    path,
    bodyBytes,
    authHash,
    popKey,
  });
}

/**
 * Convenience helper: attach the signature to a payload as `_sigbash_sig`.
 * Returns a new object — does not mutate the input.
 */
export async function attachSocketSignature(
  namespace: string,
  eventName: string,
  payload: Record<string, unknown>,
  authHash: string,
  popKey: PopKey,
): Promise<Record<string, unknown>> {
  const sig = await signSocketPayload(namespace, eventName, payload, authHash, popKey);
  return { ...payload, _sigbash_sig: sig.value };
}
