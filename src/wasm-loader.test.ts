/**
 * Tests for WASM loader
 */

import { detectEnvironment, isWasmReady } from './wasm-loader';

describe('WASM Loader', () => {
  describe('detectEnvironment', () => {
    it('should detect Node.js environment', () => {
      const env = detectEnvironment();
      expect(env).toBe('node');
    });

    it('should detect browser environment', () => {
      // Mock browser globals
      const originalWindow = global.window;
      (global as any).window = {
        document: {}
      };

      const env = detectEnvironment();
      expect(env).toBe('browser');

      // Restore
      global.window = originalWindow;
    });

    it('should detect Electron environment', () => {
      // Mock Electron in browser context
      const originalWindow = global.window;
      const originalProcess = global.process;

      (global as any).window = {
        document: {},
        process: {
          versions: {
            node: '16.0.0',
            electron: '20.0.0'
          }
        }
      };

      const env = detectEnvironment();
      expect(env).toBe('electron');

      // Restore
      global.window = originalWindow;
      global.process = originalProcess;
    });
  });

  describe('isWasmReady', () => {
    it('should return false when WASM not loaded', () => {
      const ready = isWasmReady();
      expect(ready).toBe(false);
    });

    it('should return true when WASM functions available', () => {
      // Mock WASM global functions
      (global as any).startKeyRequest = () => {};

      const ready = isWasmReady();
      expect(ready).toBe(true);

      // Cleanup
      delete (global as any).startKeyRequest;
    });
  });
});
