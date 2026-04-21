/**
 * Cryptographic utilities for Sigbash SDK.
 *
 * Triplet KEK derivation via HKDF:
 *   IKM  = UTF-8(apiKey + userKey + userSecretKey)
 *   salt = 'sigbash-kmc-v1'
 *   info = 'kmc-encryption'
 *   len  = 32 bytes → AES-256-GCM key
 *
 * Admin holds apiKey + userKey but NOT userSecretKey → cannot derive KEK.
 */

import { CryptoError, SigbashSDKError } from './errors';

/** AES-GCM IV size in bytes. */
const IV_BYTES = 12;

/**
 * Derive a 256-bit AES-GCM KEK from the credential triplet using HKDF-SHA256.
 */
export async function deriveKEK(
  apiKey: string,
  userKey: string,
  userSecretKey: string
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const ikm = enc.encode(apiKey + userKey + userSecretKey);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    ikm,
    'HKDF',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt: enc.encode('sigbash-kmc-v1'),
      info: enc.encode('kmc-encryption'),
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a KMC byte array with AES-256-GCM.
 *
 * @param kmc - Plaintext key material bytes
 * @param kek - AES-256-GCM encryption key (from deriveKEK)
 * @returns Base64-encoded string: base64(iv || ciphertext)
 */
export async function encryptKMC(kmc: Uint8Array, kek: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  // Copy kmc into a plain ArrayBuffer to satisfy WebCrypto's strict BufferSource typing
  const kmcBuf = kmc.buffer.slice(kmc.byteOffset, kmc.byteOffset + kmc.byteLength) as ArrayBuffer;

  let ciphertext: ArrayBuffer;
  try {
    ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, kmcBuf);
  } catch (err) {
    throw new CryptoError(`KMC encryption failed: ${String(err)}`, true);
  }

  const combined = new Uint8Array(IV_BYTES + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), IV_BYTES);

  // Use a loop rather than spread-to-args to avoid hitting engine argument count limits
  // for very large KMC payloads.
  let binaryStr = '';
  for (let i = 0; i < combined.length; i++) {
    binaryStr += String.fromCharCode(combined[i] as number);
  }
  return btoa(binaryStr);
}

/**
 * Decrypt an AES-256-GCM encrypted KMC string.
 *
 * @param encryptedKMC - Base64-encoded string: base64(iv || ciphertext)
 * @param kek - AES-256-GCM decryption key (from deriveKEK)
 * @returns Decrypted KMC bytes
 */
export async function decryptKMC(encryptedKMC: string, kek: CryptoKey): Promise<Uint8Array> {
  let combined: Uint8Array;
  try {
    const binaryStr = atob(encryptedKMC);
    combined = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      combined[i] = binaryStr.charCodeAt(i);
    }
  } catch {
    throw new CryptoError('Invalid base64 encoding for encrypted KMC', false);
  }

  if (combined.length <= IV_BYTES) {
    throw new CryptoError('Encrypted KMC too short to contain IV', false);
  }

  const iv = combined.slice(0, IV_BYTES);
  const ciphertext = combined.slice(IV_BYTES);

  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kek, ciphertext);
  } catch (err) {
    throw new CryptoError(`KMC decryption failed: ${String(err)}`, false);
  }

  return new Uint8Array(plaintext);
}

// ---------------------------------------------------------------------------
// CEK envelope model — Types
// ---------------------------------------------------------------------------

/** AES-GCM wrapped key (nonce + ciphertext, both hex-encoded). */
export interface WrappedKey {
  ciphertext: string;
  nonce: string;
}

/** KMC envelope auth slot. */
export interface AuthSlot {
  mode: string;
  version: string;
  credential_id: string;
  derivation_hint: string;
  created_timestamp: number;
  encrypted_cek_hex: string;   // JSON string of WrappedKey
  last_used_timestamp: number;
}

/** AES-GCM encrypted payload (base64 nonce + base64 ciphertext). */
export interface CiphertextPackage {
  nonce: string;       // base64
  ciphertext: string;  // base64
}

/** Full KMC envelope structure (matches server-side schema). */
export interface KMCEnvelope {
  version: string;
  envelope_id: string;
  network_type: string;
  created_timestamp: number;
  auth_slots: AuthSlot[];
  ciphertext_package: CiphertextPackage;
  last_used_timestamp: number;
}

/** Options for buildKMCEnvelope(). */
export interface EnvelopeOpts {
  apiKey: string;
  userKey: string;
  userSecretKey: string;
  userRecoveryKEK: Uint8Array;
  authHash: string;
  network: string;
}

/**
 * The versioned JSON shape written into the enc_kek2 column by the SDK (api credential type).
 * Version 'api-v1': CEK wrapped under deriveUserRecoveryKEK(apiKey, userKey, userSecretKey).
 *   Fields: { ciphertext: hex, nonce: hex, version: 'api-v1' }
 *
 * The web/WebAuthn path writes a structurally identical JSON object but with
 * base64-encoded fields and version 'webauthn-v1':
 *   { ciphertext: base64, nonce: base64, version: 'webauthn-v1' }
 *
 * Rows written before versioning was introduced lack a version field and are
 * implicitly treated as 'webauthn-v1' legacy by the Go side.
 */

/** Result of buildKMCEnvelope(). */
export interface EnvelopeResult {
  envelope: KMCEnvelope;
  /**
   * JSON string of { ciphertext: hex, nonce: hex, version: 'api-v1' }.
   * CEK wrapped under the user recovery KEK (requires userSecretKey to unwrap —
   * never derivable by the server/admin alone).
   * Must NOT be consumed by the WebAuthn (webauthn-v1) decryption path.
   */
  enc_kek2: string;
}

// ---------------------------------------------------------------------------
// CEK envelope model — Functions
// ---------------------------------------------------------------------------

/**
 * Generate a fresh 32-byte Content Encryption Key (CEK).
 */
export function generateCEK(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Wrap a CEK with an AES-256-GCM wrapping key.
 * Returns {ciphertext: hex, nonce: hex}.
 */
export async function wrapCEK(cek: Uint8Array, wrappingKeyBytes: Uint8Array): Promise<WrappedKey> {
  const wrappingKeyBuf = wrappingKeyBytes.buffer.slice(
    wrappingKeyBytes.byteOffset, wrappingKeyBytes.byteOffset + wrappingKeyBytes.byteLength
  ) as ArrayBuffer;
  const wrappingKey = await crypto.subtle.importKey(
    'raw',
    wrappingKeyBuf,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cekBuf = cek.buffer.slice(cek.byteOffset, cek.byteOffset + cek.byteLength) as ArrayBuffer;
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, wrappingKey, cekBuf);
  const toHex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  return {
    ciphertext: toHex(new Uint8Array(ciphertext)),
    nonce: toHex(nonce),
  };
}

/**
 * Unwrap a CEK that was wrapped with wrapCEK().
 */
export async function unwrapCEK(wrapped: WrappedKey, wrappingKeyBytes: Uint8Array): Promise<Uint8Array> {
  const wrappingKeyBuf = wrappingKeyBytes.buffer.slice(
    wrappingKeyBytes.byteOffset, wrappingKeyBytes.byteOffset + wrappingKeyBytes.byteLength
  ) as ArrayBuffer;
  const wrappingKey = await crypto.subtle.importKey(
    'raw',
    wrappingKeyBuf,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  const fromHex = (s: string) => Uint8Array.from(s.match(/.{2}/g)!.map(b => parseInt(b, 16)));
  const nonce = fromHex(wrapped.nonce);
  const ciphertextBytes = fromHex(wrapped.ciphertext);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, wrappingKey, ciphertextBytes);
  return new Uint8Array(plaintext);
}

/**
 * Derive raw 32-byte KEK bytes from the credential triplet.
 * Uses the same HKDF parameters as deriveKEK() but returns raw bytes instead of a CryptoKey.
 */
export async function deriveKEKRaw(
  apiKey: string,
  userKey: string,
  userSecretKey: string
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const ikm = enc.encode(apiKey + userKey + userSecretKey);
  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: enc.encode('sigbash-kmc-v1'),
      info: enc.encode('kmc-encryption'),
      hash: 'SHA-256',
    },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}

/**
 * Derive the user recovery KEK from the credential triplet.
 * Uses different HKDF salt/info from the credential KEK — requires userSecretKey.
 * admins cannot derive this KEK without userSecretKey.
 *
 * KEK = HKDF(apiKey ∥ userKey ∥ userSecretKey,
 *            salt='sigbash-kmc-v1-user-recovery',
 *            info='kmc-encryption-recovery')
 */
export async function deriveUserRecoveryKEK(
  apiKey: string,
  userKey: string,
  userSecretKey: string
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const ikm = enc.encode(apiKey + userKey + userSecretKey);
  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: enc.encode('sigbash-kmc-v1-user-recovery'),
      info: enc.encode('kmc-encryption-recovery'),
      hash: 'SHA-256',
    },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}

/**
 * Build a KMC envelope encrypting `kmc` under a fresh CEK.
 * The CEK is independently wrapped for:
 *   1. The credential auth slot (credential-triplet KEK)
 *   2. enc_kek2 (user recovery KEK — requires userSecretKey)
 */
export async function buildKMCEnvelope(kmc: object, opts: EnvelopeOpts): Promise<EnvelopeResult> {
  const enc = new TextEncoder();

  // 1. Fresh random CEK
  const cek = generateCEK();

  // 2. Encrypt KMC payload with CEK (AES-256-GCM)
  const cekBufForImport = cek.buffer.slice(cek.byteOffset, cek.byteOffset + cek.byteLength) as ArrayBuffer;
  const cekKey = await crypto.subtle.importKey('raw', cekBufForImport, { name: 'AES-GCM' }, false, ['encrypt']);
  const kmcBytes = enc.encode(JSON.stringify(kmc));
  const kmcBuf = kmcBytes.buffer.slice(kmcBytes.byteOffset, kmcBytes.byteOffset + kmcBytes.byteLength) as ArrayBuffer;
  const payloadNonce = crypto.getRandomValues(new Uint8Array(12));
  const payloadCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: payloadNonce }, cekKey, kmcBuf);

  const toB64 = (b: Uint8Array): string => {
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
    return btoa(s);
  };
  const ciphertextPackage: CiphertextPackage = {
    nonce: toB64(payloadNonce),
    ciphertext: toB64(new Uint8Array(payloadCiphertext)),
  };

  // 3. Wrap CEK with credential KEK for the auth slot
  const credKEKRaw = await deriveKEKRaw(opts.apiKey, opts.userKey, opts.userSecretKey);
  const credWrapped = await wrapCEK(cek, credKEKRaw);

  // 4. Wrap CEK with user recovery KEK for enc_kek2
  const recoveryWrapped = await wrapCEK(cek, opts.userRecoveryKEK);

  // 5. Assemble envelope
  const now = Math.floor(Date.now() / 1000);
  const envId =
    'envelope-' +
    Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

  const authSlot: AuthSlot = {
    mode: 'api',
    version: '1.0',
    credential_id: opts.authHash,
    derivation_hint: `kmc-api-${opts.authHash.slice(0, 16)}-m/0`,
    created_timestamp: now,
    encrypted_cek_hex: JSON.stringify(credWrapped),
    last_used_timestamp: now,
  };

  const envelope: KMCEnvelope = {
    version: '1.0',
    envelope_id: envId,
    network_type: opts.network,
    created_timestamp: now,
    auth_slots: [authSlot],
    ciphertext_package: ciphertextPackage,
    last_used_timestamp: now,
  };

  // Embed the credential-type version tag so the WebAuthn recovery path can
  // detect and reject an enc_kek2 blob that belongs to the api credential type.
  return { envelope, enc_kek2: JSON.stringify({ ...recoveryWrapped, version: 'api-v1' }) };
}

// ---------------------------------------------------------------------------
// enc_kek2 parsing helper
// ---------------------------------------------------------------------------

/**
 * Parse and validate an enc_kek2 JSON string from the server.
 *
 * Accepts only blobs tagged with version 'api-v1' (the format written by
 * buildKMCEnvelope in the SDK path).  Throws SigbashSDKError with code
 * 'ENC_KEK2_VERSION_MISMATCH' if the blob is present but tagged for a
 * different credential type (e.g. 'webauthn-v1'), preventing the SDK from
 * accidentally consuming a WebAuthn-path enc_kek2.
 *
 * A missing version field is treated as a legacy row — accepted for
 * backward compatibility with rows written before versioning was introduced.
 * Callers should not rely on this tolerance for new rows.
 *
 * @param enc_kek2_json - Raw JSON string stored in the enc_kek2 column
 * @returns Parsed object with ciphertext, nonce, and optional version
 * @throws SigbashSDKError if the version tag identifies a non-api credential type
 */
export function parseEncKek2(
  enc_kek2_json: string
): { ciphertext: string; nonce: string; version?: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(enc_kek2_json);
  } catch {
    throw new CryptoError('enc_kek2: invalid JSON', false);
  }

  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    typeof (parsed as Record<string, unknown>).ciphertext !== 'string' ||
    typeof (parsed as Record<string, unknown>).nonce !== 'string'
  ) {
    throw new CryptoError('enc_kek2: missing required ciphertext or nonce fields', false);
  }

  const obj = parsed as { ciphertext: string; nonce: string; version?: string };

  // If a version tag is present, verify it is the api-v1 format.
  // An absent version is tolerated as a legacy row (pre-versioning).
  if (obj.version !== undefined && obj.version !== 'api-v1') {
    throw new SigbashSDKError(
      `enc_kek2 format incompatible with api credential type: found version '${obj.version}', expected 'api-v1'`,
      'ENC_KEK2_VERSION_MISMATCH'
    );
  }

  return obj;
}

/**
 * Derive the 32-byte seed that feeds the WASM SeedManager used during POET policy
 * compilation.  Must use the same HKDF parameters every time for a given credential
 * triplet so that the compiled policy_root is stable across calls.
 *
 * HKDF-SHA256:
 *   IKM  = UTF-8(apiKey + userKey + userSecretKey)
 *   salt = 'sigbash-policy-salt-v1'
 *   info = 'poet-policy-compilation-salt'
 *   len  = 32 bytes
 */
export async function derivePolicySalt(
  apiKey: string,
  userKey: string,
  userSecretKey: string
): Promise<string> {
  const enc = new TextEncoder();
  const ikm = enc.encode(apiKey + userKey + userSecretKey);
  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: enc.encode('sigbash-policy-salt-v1'),
      info: enc.encode('poet-policy-compilation-salt'),
      hash: 'SHA-256',
    },
    baseKey,
    256
  );
  const bytes = new Uint8Array(bits);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Decrypt a KMC envelope using the recovery KEK path (enc_kek2).
 *
 * This is the recovery-path mirror of decryptKMCEnvelope().  Use it when the
 * credential auth slot is unavailable (e.g. userSecretKey was lost but the
 * pre-derived recoveryKEK was saved in an SdkRecoveryKit).
 *
 * @param envelope         - Full KMC envelope from the server
 * @param wrappedCEK       - Already-parsed { ciphertext: hex, nonce: hex } — caller must validate version
 * @param recoveryKEKBytes - Pre-derived userRecoveryKEK bytes (32 bytes)
 * @throws CryptoError     if the recovery KEK is wrong or decryption fails
 */
export async function decryptKMCFromRecoveryKEK(
  envelope: KMCEnvelope,
  wrappedCEK: WrappedKey,
  recoveryKEKBytes: Uint8Array
): Promise<object> {
  let cek: Uint8Array;
  try {
    cek = await unwrapCEK(wrappedCEK, recoveryKEKBytes);
  } catch (err) {
    throw new CryptoError(`KMC recovery CEK unwrap failed (wrong recoveryKEK?): ${String(err)}`, false);
  }

  // 3. Import raw CEK bytes as AES-GCM CryptoKey for decryption.
  const cekBuf = cek.buffer.slice(cek.byteOffset, cek.byteOffset + cek.byteLength) as ArrayBuffer;
  const cekKey = await crypto.subtle.importKey('raw', cekBuf, { name: 'AES-GCM' }, false, ['decrypt']);

  // 4. Decode ciphertext_package (base64 nonce + base64 ciphertext).
  const fromB64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const nonce = fromB64(envelope.ciphertext_package.nonce);
  const ciphertextBytes = fromB64(envelope.ciphertext_package.ciphertext);

  // 5. AES-GCM decrypt and JSON-parse the KMC payload.
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, cekKey, ciphertextBytes);
  } catch (err) {
    throw new CryptoError(`KMC recovery envelope decryption failed: ${String(err)}`, false);
  }

  return JSON.parse(new TextDecoder().decode(new Uint8Array(plaintext))) as object;
}

/**
 * Decrypt a KMC envelope using the credential-triplet KEK.
 * Finds the 'api' auth slot, unwraps the CEK, and decrypts the ciphertext.
 */
export async function decryptKMCEnvelope(
  envelope: KMCEnvelope,
  apiKey: string,
  userKey: string,
  userSecretKey: string
): Promise<object> {
  const slot = envelope.auth_slots.find(s => s.mode === 'api');
  if (!slot) {
    throw new CryptoError('No api auth slot found in KMC envelope', false);
  }

  const credKEKRaw = await deriveKEKRaw(apiKey, userKey, userSecretKey);
  const wrappedCEK = JSON.parse(slot.encrypted_cek_hex) as WrappedKey;
  let cek: Uint8Array;
  try {
    cek = await unwrapCEK(wrappedCEK, credKEKRaw);
  } catch (err) {
    throw new CryptoError(`KMC CEK unwrap failed (wrong credential key?): ${String(err)}`, false);
  }

  const cekBuf = cek.buffer.slice(cek.byteOffset, cek.byteOffset + cek.byteLength) as ArrayBuffer;
  const cekKey = await crypto.subtle.importKey('raw', cekBuf, { name: 'AES-GCM' }, false, ['decrypt']);
  const fromB64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const nonce = fromB64(envelope.ciphertext_package.nonce);
  const ciphertextBytes = fromB64(envelope.ciphertext_package.ciphertext);

  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, cekKey, ciphertextBytes);
  } catch (err) {
    throw new CryptoError(`KMC envelope decryption failed: ${String(err)}`, false);
  }

  return JSON.parse(new TextDecoder().decode(new Uint8Array(plaintext))) as object;
}
