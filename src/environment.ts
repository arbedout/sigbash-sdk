/**
 * Environment detection — shared by wasm-loader and prove-worker-manager.
 */

export type Environment = 'browser' | 'node' | 'electron' | 'unknown';

export function detectEnvironment(): Environment {
  // Check for browser
  if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
    // Check for Electron in browser context
    if (typeof (window as any).process !== 'undefined' &&
        typeof (window as any).process.versions !== 'undefined' &&
        (window as any).process.versions.electron) {
      return 'electron';
    }
    return 'browser';
  }

  // Check for Node.js
  if (typeof process !== 'undefined' &&
      process.versions != null &&
      process.versions.node != null) {
    // Check for Electron in Node context
    if (process.versions.electron) {
      return 'electron';
    }
    return 'node';
  }

  return 'unknown';
}
