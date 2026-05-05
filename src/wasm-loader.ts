/**
 * Universal WASM Loader for Sigbash SDK
 * Supports: Browser, Node.js, and Electron environments
 * Features: Environment detection, integrity verification, cross-platform loading
 */

import { getProveWorkerManager } from './prove-worker-manager';
export type { ProveWorkerManager, ProveRequest, ProveWorkerManagerStatus } from './prove-worker-manager';
export { getProveWorkerManager } from './prove-worker-manager';

import { detectEnvironment, type Environment } from './environment';
// Re-export from shared module (keeps public API stable).
export { detectEnvironment, type Environment } from './environment';

/**
 * WASM loader options
 */
export interface WasmLoaderOptions {
  wasmUrl: string;
  expectedHash?: string;
  onProgress?: (progress: number, stage: string) => void;
}

/**
 * WASM loader result
 */
export interface WasmLoaderResult {
  instance: WebAssembly.Instance;
  module: WebAssembly.Module;
  go: any;
  environment: Environment;
}

/**
 * Compute SHA-384 hash of ArrayBuffer
 */
async function computeSHA384(buffer: ArrayBuffer): Promise<string> {
  const env = detectEnvironment();

  if (env === 'browser' || env === 'electron') {
    // Browser/Electron: Use Web Crypto API
    if (!crypto || !crypto.subtle) {
      throw new Error('Web Crypto API not available for integrity verification');
    }

    const hashBuffer = await crypto.subtle.digest('SHA-384', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
  } else if (env === 'node') {
    // Node.js: Use crypto module
    try {
      const crypto = await import('crypto');
      const hash = crypto.createHash('sha384');
      hash.update(Buffer.from(buffer));
      return hash.digest('hex');
    } catch (err) {
      throw new Error(`Failed to compute hash in Node.js: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  throw new Error(`Cannot compute hash in unknown environment`);
}

/**
 * Constant-time string comparison to prevent timing attacks
 * Prevents attackers from reconstructing expected hash byte-by-byte
 */
function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Verify WASM binary integrity
 */
async function verifyIntegrity(
  wasmBuffer: ArrayBuffer,
  expectedHash: string,
  onProgress?: (progress: number, stage: string) => void
): Promise<void> {
  onProgress?.(70, 'Verifying WASM integrity...');

  const actualHash = await computeSHA384(wasmBuffer);

  if (!constantTimeCompare(actualHash, expectedHash)) {
    // Redact hashes in production to prevent information disclosure
    const errorMessage = 'WASM integrity check failed. Binary may be corrupted or compromised.';
    throw new Error(errorMessage);
  }

  onProgress?.(75, 'WASM integrity verified');
}

/**
 * Validate WASM URL for security
 * Ensures HTTPS in production and valid URL format
 */
function validateWasmUrl(url: string, env: Environment): void {
  if (env === 'browser' || env === 'electron') {
    // Check for secure protocol in production
    if (!url.startsWith('https://') && !url.startsWith('blob:') && !url.startsWith('/')) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('WASM URL must use HTTPS in production (HTTP is insecure)');
      }
      console.warn('[Sigbash SDK] WARNING: Loading WASM over insecure HTTP (development only)');
    }

    // Validate URL format
    try {
      new URL(url, typeof window !== 'undefined' ? window.location.href : 'http://localhost');
    } catch (err) {
      throw new Error(`Invalid WASM URL format: ${url}`);
    }
  }
}

/**
 * Load WASM binary from URL (browser/Electron)
 */
async function loadWasmBrowser(
  wasmUrl: string,
  onProgress?: (progress: number, stage: string) => void
): Promise<ArrayBuffer> {
  onProgress?.(10, 'Fetching WASM binary...');

  const response = await fetch(wasmUrl);
  if (!response.ok) {
    throw new Error(`Failed to fetch WASM binary: ${response.status} ${response.statusText}`);
  }

  onProgress?.(50, 'Downloading WASM...');

  const wasmBuffer = await response.arrayBuffer();

  onProgress?.(60, 'WASM downloaded');

  return wasmBuffer;
}

/**
 * Load WASM binary from filesystem (Node.js)
 */
async function loadWasmNode(
  wasmPath: string,
  onProgress?: (progress: number, stage: string) => void
): Promise<ArrayBuffer> {
  // If the path is an HTTP/HTTPS URL, fetch over the network
  if (wasmPath.startsWith('https://') || wasmPath.startsWith('http://')) {
    onProgress?.(10, 'Fetching WASM from network...');

    try {
      // Use global fetch if available (Node.js 18+), otherwise fall back to http/https modules
      if (typeof fetch === 'function') {
        const response = await fetch(wasmPath);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status} ${response.statusText}`);
        }
        onProgress?.(50, 'Downloading WASM...');
        const buffer = await response.arrayBuffer();
        onProgress?.(60, 'WASM downloaded from network');
        return buffer;
      } else {
        // Older Node.js: use built-in http/https module
        const buffer = await new Promise<Buffer>((resolve, reject) => {
          const protocol = wasmPath.startsWith('https://') ? require('https') : require('http');
          protocol.get(wasmPath, (res: any) => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              reject(new Error(`HTTP ${res.statusCode} ${res.statusMessage}`));
              res.resume();
              return;
            }
            const chunks: Buffer[] = [];
            res.on('data', (chunk: Buffer) => chunks.push(chunk));
            res.on('end', () => resolve(Buffer.concat(chunks)));
            res.on('error', reject);
          }).on('error', reject);
        });
        onProgress?.(60, 'WASM downloaded from network');
        return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) as ArrayBuffer;
      }
    } catch (err) {
      throw new Error(
        `Failed to fetch WASM from URL: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  onProgress?.(10, 'Reading WASM from filesystem...');

  try {
    const fs = await import('fs/promises');
    const path = await import('path');

    // Resolve absolute path
    const resolvedPath = path.resolve(wasmPath);

    onProgress?.(30, 'Loading WASM file...');

    const wasmBuffer = await fs.readFile(resolvedPath);

    onProgress?.(60, 'WASM loaded from disk');

    return wasmBuffer.buffer;
  } catch (err) {
    throw new Error(
      `Failed to read WASM file from filesystem: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

/**
 * Initialize Go WASM runtime
 */
async function initializeGoRuntime(env: Environment): Promise<any> {
  // In browser/Electron, Go runtime should be loaded via script tag
  if (env === 'browser' || env === 'electron') {
    if (typeof (globalThis as any).Go === 'undefined') {
      throw new Error(
        'Go WASM runtime not found. Please include wasm_exec.js before loading the SDK.'
      );
    }
    return new (globalThis as any).Go();
  }

  // In Node.js, require wasm_exec.js
  if (env === 'node') {
    try {
      // In ESM context require is not defined; use createRequire as fallback
      // (typeof require is safe — won't throw even when require is not declared)
      let requireFn: NodeRequire;
      if (typeof require !== 'undefined') {
        requireFn = require;
      } else {
        const { createRequire } = await import('module');
        requireFn = createRequire(process.cwd() + '/');
      }

      // R2: Load wasm_exec.js from bundled SDK package
      // Try multiple resolution paths for compatibility
      let wasmExecPath: string;
      try {
        // First try: resolve from node_modules/@sigbash/sdk/wasm/
        wasmExecPath = requireFn.resolve('@sigbash/sdk/wasm/wasm_exec.js');
      } catch {
        // Second try: resolve relative to this file (local development)
        const path = requireFn('path');
        const dirName = typeof __dirname !== 'undefined'
          ? __dirname
          : path.dirname(requireFn.resolve('@sigbash/sdk'));
        wasmExecPath = path.resolve(dirName, '../wasm/wasm_exec.js');
      }

      requireFn(wasmExecPath);

      if (typeof (global as any).Go === 'undefined') {
        throw new Error('Go WASM runtime failed to initialize after loading wasm_exec.js');
      }

      return new (global as any).Go();
    } catch (err) {
      throw new Error(
        `Failed to load Go WASM runtime in Node.js: ${err instanceof Error ? err.message : String(err)}. ` +
        `Ensure wasm_exec.js is bundled in the SDK package at wasm/wasm_exec.js.`
      );
    }
  }

  throw new Error(`Cannot initialize Go runtime in unknown environment`);
}

/**
 * Load and instantiate WASM module
 */
export async function loadWasm(options: WasmLoaderOptions): Promise<WasmLoaderResult> {
  const { wasmUrl, expectedHash, onProgress } = options;

  onProgress?.(0, 'Detecting environment...');
  const env = detectEnvironment();

  if (env === 'unknown') {
    throw new Error('Unknown runtime environment. Sigbash SDK requires browser, Node.js, or Electron.');
  }

  onProgress?.(5, `Environment detected: ${env}`);

  // Validate URL security
  validateWasmUrl(wasmUrl, env);

  // Load WASM binary
  let wasmBuffer: ArrayBuffer;
  if (env === 'browser' || env === 'electron') {
    wasmBuffer = await loadWasmBrowser(wasmUrl, onProgress);
  } else {
    wasmBuffer = await loadWasmNode(wasmUrl, onProgress);
  }

  // R4: Mandatory integrity verification in production
  if (expectedHash) {
    await verifyIntegrity(wasmBuffer, expectedHash, onProgress);
  } else if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'WASM integrity hash required in production mode. ' +
      'Set expectedHash option to enable cryptographic verification.'
    );
  } else {
    console.warn('[Sigbash SDK] WARNING: WASM integrity verification disabled (development only)');
  }

  onProgress?.(80, 'Initializing Go runtime...');

  // Initialize Go runtime
  const go = await initializeGoRuntime(env);

  onProgress?.(85, 'Instantiating WASM module...');

  // Instantiate WASM
  const { instance, module } = await WebAssembly.instantiate(wasmBuffer, go.importObject);

  onProgress?.(95, 'Starting Go runtime...');

  // Run Go program (non-blocking)
  go.run(instance);

  // Store the WASM URL on globalThis so workers can locate the binary.
  (globalThis as Record<string, unknown>)['_sigbashWasmUrl'] = wasmUrl;

  // Warm up the WebCrypto / OpenSSL thread pool. Node.js lazily initializes
  // libuv worker threads on the first crypto.subtle.digest call. Without this,
  // the first Ligero commit's batch SHA-256 pays a ~2s cold-start penalty for
  // thread creation + OpenSSL init. An empty digest is essentially free (~0ms)
  // but forces the pool to initialize.
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    crypto.subtle.digest('SHA-256', new Uint8Array(0)).catch(() => {});
  }

  // Eagerly initialize the worker pool in the background.
  // Don't await — let workers load while the main thread continues.
  // Failures are silently swallowed; the manager falls back to main-thread proving.
  getProveWorkerManager().init().catch(() => {
    // Intentionally ignored — fallback mode will activate.
  });

  onProgress?.(100, 'WASM loaded successfully');

  return {
    instance,
    module,
    go,
    environment: env
  };
}

/**
 * Check if WASM is available and initialized
 */
export function isWasmReady(): boolean {
  // Check for key WASM exports that should be available after initialization
  const globalObj = (typeof window !== 'undefined' ? window : global) as any;

  return (
    typeof globalObj.startKeyRequest === 'function' ||
    typeof globalObj.verifyPasskeyWithPin === 'function' ||
    typeof globalObj.SigbashWASM_SignPSBTBlind === 'function'
  );
}

/**
 * Wait for WASM to be ready (with timeout)
 */
export async function waitForWasm(timeoutMs: number = 10000): Promise<void> {
  const startTime = Date.now();

  while (!isWasmReady()) {
    if (Date.now() - startTime > timeoutMs) {
      throw new Error(`WASM initialization timeout after ${timeoutMs}ms`);
    }

    // Wait 100ms before checking again
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}
