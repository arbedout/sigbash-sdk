/**
 * Audit log key derivation and ciphertext helpers.
 *
 * When the org has private_logs = false, log entries are encrypted with a key
 * derivable from apiKey + userKey only. The end user's userSecretKey is NOT
 * required, so the org admin (who holds apiKey + userKey for all org users)
 * can decrypt every entry.
 *
 * When private_logs = true, the SDK MUST defer to the existing user-DEK path
 * (WASM-derived from MasterSeed) and the admin will be unable to decrypt.
 */

import { createHmac, randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export const AUDIT_LOG_KEY_LABEL = 'sigbash-audit-log-v1';

/** HMAC-SHA256(label, apiKey || userKey) — 32-byte AES-256 key. */
export function deriveAdminAuditDek(apiKey: string, userKey: string): Buffer {
  const ak = Buffer.from(apiKey, 'hex');
  const uk = Buffer.from(userKey, 'hex');
  return createHmac('sha256', Buffer.from(AUDIT_LOG_KEY_LABEL, 'utf8'))
    .update(Buffer.concat([ak, uk]))
    .digest();
}

/**
 * The plaintext audit log payload. ALL fields live INSIDE the ciphertext —
 * none are visible to the server. Only `key_id` and the opaque ciphertext
 * are sent on the wire.
 */
export interface AuditLogEntry {
  txid?: string;
  psbtId?: string;
  amountSats?: number;
  recipient?: string;
  network: string;
  status: string;
  timestamp: number;       // client-side wall clock when the entry was created
  type?: string;
  notes?: string;
  [k: string]: unknown;
}

/** AES-256-GCM encrypt JSON.stringify(entry). Output mirrors EncryptedPackage from WASM. */
export function encryptAuditEntry(entry: AuditLogEntry, dek: Buffer): string {
  if (dek.length !== 32) throw new Error('audit log DEK must be 32 bytes');
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dek, nonce);
  const pt = Buffer.from(JSON.stringify(entry), 'utf8');
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    nonce: nonce.toString('base64'),
    ciphertext: Buffer.concat([ct, tag]).toString('base64'),
  });
}

export function decryptAuditEntry(blob: string, dek: Buffer): AuditLogEntry {
  if (dek.length !== 32) throw new Error('audit log DEK must be 32 bytes');
  const pkg = JSON.parse(blob);
  const nonce = Buffer.from(pkg.nonce, 'base64');
  const combined = Buffer.from(pkg.ciphertext, 'base64');
  const tag = combined.subarray(combined.length - 16);
  const ct = combined.subarray(0, combined.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', dek, nonce);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}

/**
 * Verify a chain of receipts forms an unbroken HMAC chain.
 * Pure client-side check using stored receipts; does NOT require the server
 * HMAC key (the server's MAC is treated as opaque — the client only verifies
 * monotonicity and continuity).
 */
export function verifyReceiptChain(
  receipts: Array<{ server_seq: number; chain_mac: string }>
): boolean {
  for (let i = 0; i < receipts.length; i++) {
    if (receipts[i].server_seq !== i + 1) return false;
    if (!/^[0-9a-f]{64}$/.test(receipts[i].chain_mac)) return false;
  }
  return true;
}
