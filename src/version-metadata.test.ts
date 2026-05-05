/**
 * Tests for WASM version metadata utilities
 */

import { buildWasmUrl, formatSRIHash } from './version-metadata';

describe('Version Metadata', () => {
  describe('buildWasmUrl', () => {
    it('should build URL from server and relative path', () => {
      const url = buildWasmUrl('https://api.sigbash.com', {
        wasm_version: 'sigbash_20260202_152658.wasm',
        wasm_sha384: 'abc123',
        wasm_path: '/web/sigbash_20260202_152658.wasm'
      });

      expect(url).toBe('https://api.sigbash.com/web/sigbash_20260202_152658.wasm');
    });

    it('should handle server URL with trailing slash', () => {
      const url = buildWasmUrl('https://api.sigbash.com/', {
        wasm_version: 'sigbash_20260202_152658.wasm',
        wasm_sha384: 'abc123',
        wasm_path: '/web/sigbash_20260202_152658.wasm'
      });

      expect(url).toBe('https://api.sigbash.com/web/sigbash_20260202_152658.wasm');
    });

    it('should handle absolute WASM path', () => {
      const url = buildWasmUrl('https://api.sigbash.com', {
        wasm_version: 'sigbash_20260202_152658.wasm',
        wasm_sha384: 'abc123',
        wasm_path: 'https://cdn.sigbash.com/wasm/sigbash_20260202_152658.wasm'
      });

      expect(url).toBe('https://cdn.sigbash.com/wasm/sigbash_20260202_152658.wasm');
    });

    it('should handle path without leading slash', () => {
      const url = buildWasmUrl('https://api.sigbash.com', {
        wasm_version: 'sigbash_20260202_152658.wasm',
        wasm_sha384: 'abc123',
        wasm_path: 'web/sigbash_20260202_152658.wasm'
      });

      expect(url).toBe('https://api.sigbash.com/web/sigbash_20260202_152658.wasm');
    });
  });

  describe('formatSRIHash', () => {
    it('should return SRI format hash as-is', () => {
      const hash = 'sha384-LEFpJGAHIsGM56i5DJYJZWv6ZzUxffPm5xCgcVILU/R6HoCLOzIZK/ixIxsAsal+';
      const formatted = formatSRIHash(hash);
      expect(formatted).toBe(hash);
    });

    it('should format hex hash to SRI format', () => {
      const hexHash = '2c416924'; // Short example
      const formatted = formatSRIHash(hexHash, 'sha256');
      expect(formatted).toMatch(/^sha256-/);
    });
  });
});
