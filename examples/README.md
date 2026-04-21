# Sigbash SDK Examples

This directory contains runnable usage examples for the `@sigbash/sdk` package.

## Examples

### 1. Complete Node.js Workflow — `basic-usage.js`

Demonstrates the full signing lifecycle:
- Load WASM
- Create `SigbashClient`
- Build a policy with `conditionConfigToPoetPolicy`
- Register a key with `createKey()`
- Retrieve key material with `getKey()`
- Sign a PSBT with `signPSBT()`
- Handle `KeyIndexExistsError` and `PolicyCompileError`

**Run:**
```bash
# Build the SDK first (from sdk/ directory)
npm run build

# Set credentials (or edit the defaults in the file)
export SIGBASH_API_KEY=your-api-key
export SIGBASH_USER_KEY=alice
export SIGBASH_SECRET_KEY=your-strong-secret

# Optional — set a real base64 PSBT to test actual signing
export SIGBASH_TEST_PSBT=<base64-psbt>

node examples/basic-usage.js
```

### 2. Browser Example — `browser-example.html`

Demonstrates loading the SDK in a browser context.

**Run:**
```bash
# Serve the sdk/ directory with any static file server
cd /path/to/sdk
npx http-server .

# Open: http://localhost:8080/examples/browser-example.html
```

---

## WASM Delivery

The Sigbash WASM binary is **not** bundled in the npm package.  Load it at
runtime from the CDN or your own server:

```javascript
import { loadWasm } from '@sigbash/sdk';
await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });
```

For production, fetch the current `wasm_sha384` from your server's auth
endpoint and pass it as `expectedHash` to enable integrity verification.

---

## Policy Quick Reference

See `CONDITION_TYPES` in the SDK for the full parameter schema:

```javascript
const { CONDITION_TYPES } = require('@sigbash/sdk');
console.log(Object.keys(CONDITION_TYPES));
// All 25 condition types with params and examples
```
