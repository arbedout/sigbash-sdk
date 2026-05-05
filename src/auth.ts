/**
 * Double SHA256 authentication hash utilities for Sigbash SDK.
 *
 * Auth hash: DSHA256(apiKey || userKey)
 * Org-level hash: DSHA256(apiKey || apiKey) — identifies org without exposing raw key
 */

/**
 * Compute double SHA256: SHA256(SHA256(data)) of the concatenation of two strings.
 *
 * @param a - First string component (e.g. apiKey)
 * @param b - Second string component (e.g. userKey or empty string)
 * @returns Lowercase hex-encoded 64-character hash
 */
export async function doubleSha256(a: string, b: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(a + b);
  const inner = await crypto.subtle.digest('SHA-256', data);
  const outer = await crypto.subtle.digest('SHA-256', inner);
  return Array.from(new Uint8Array(outer))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Validate that a string is a 64-character lowercase hex hash.
 *
 * @param hash - The hash string to validate
 * @returns true if valid, false otherwise
 */
export function validateAuthHash(hash: string): boolean {
  return /^[0-9a-f]{64}$/.test(hash);
}
