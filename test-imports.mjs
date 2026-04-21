/**
 * Quick test to verify all exports are accessible
 */

import {
  // WASM Loader
  loadWasm,
  detectEnvironment,
  isWasmReady,
  waitForWasm,

  // Version Metadata
  buildWasmUrl,
  sha384ToBase64,
  formatSRIHash,

  // Errors
  SigbashError,
  PolicyValidationError,
  AuthenticationError,
  WasmError,
  NetworkMismatchError,
  CryptoError,
  ServerError,
  TimeoutError,
  parseServerError,

  // Version
  SDK_VERSION
} from './dist/index.mjs';

console.log('✅ All exports loaded successfully!\n');

console.log('SDK Version:', SDK_VERSION);
console.log('Environment:', detectEnvironment());
console.log('WASM Ready:', isWasmReady());

console.log('\n✅ Import test passed!');
