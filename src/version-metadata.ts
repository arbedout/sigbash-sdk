/**
 * WASM version metadata management
 * Allows SDK to pin to specific WASM versions using data from API JWT response
 */

/**
 * WASM version metadata (from JWT response)
 */
export interface WasmVersionMetadata {
  /**
   * WASM version identifier (e.g., "sigbash_20260202_152658.wasm")
   */
  wasm_version: string;

  /**
   * SHA-384 hash of WASM binary (for integrity verification)
   */
  wasm_sha384: string;

  /**
   * URL path to WASM binary on server
   */
  wasm_path: string;
}

/**
 * Build WASM URL from version metadata
 */
export function buildWasmUrl(serverUrl: string, metadata: WasmVersionMetadata): string {
  // Remove trailing slash from server URL
  const baseUrl = serverUrl.replace(/\/$/, '');

  // If path is absolute, use it directly
  if (metadata.wasm_path.startsWith('http://') || metadata.wasm_path.startsWith('https://')) {
    return metadata.wasm_path;
  }

  // Otherwise, construct URL from server base
  const path = metadata.wasm_path.startsWith('/') ? metadata.wasm_path : `/${metadata.wasm_path}`;
  return `${baseUrl}${path}`;
}

/**
 * Extract SHA-256 hash from SHA-384 (for backward compatibility)
 * Note: SHA-384 is preferred for integrity verification, but if client
 * expects SHA-256, we need to compute it separately
 */
export function sha384ToBase64(sha384Hex: string): string {
  // Convert hex to base64 for SRI format
  const bytes = sha384Hex.match(/.{2}/g)?.map(byte => parseInt(byte, 16)) || [];
  // Use Buffer in Node.js (avoids btoa which is browser-only in some environments)
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  const binary = String.fromCharCode(...bytes);
  return btoa(binary);
}

/**
 * Format hash for SRI format (used by WASM integrity checker)
 */
export function formatSRIHash(hash: string, algorithm: 'sha256' | 'sha384' = 'sha384'): string {
  // If already in SRI format, return as-is
  if (hash.startsWith('sha256-') || hash.startsWith('sha384-')) {
    return hash;
  }

  // Otherwise, assume hex and convert to base64
  return `${algorithm}-${sha384ToBase64(hash)}`;
}
