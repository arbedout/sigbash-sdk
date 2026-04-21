/**
 * Sigbash SDK — Node.js complete workflow example
 *
 * Demonstrates the full bootstrap flow:
 *   1. Load WASM
 *   2. Create SigbashClient
 *   3. Define a policy using conditionConfigToPoetPolicy
 *   4. Register a key with createKey()
 *   5. Retrieve key material with getKey()
 *   6. Sign a PSBT with signPSBT()
 *   7. Handle errors
 *
 * Prerequisites:
 *   - A Sigbash server URL and API key
 *   - A funded P2TR UTXO on the address returned by createKey()
 *   - A PSBT spending that UTXO (use bitcoinjs-lib or Bitcoin Core to create one)
 */

const { loadWasm, SigbashClient, conditionConfigToPoetPolicy, KeyIndexExistsError, PolicyCompileError } = require('@sigbash/sdk');

async function main() {
  // ── Step 1: Load WASM ──────────────────────────────────────────────────────
  // The WASM binary is delivered via CDN — not bundled in the npm package.
  // In production you would fetch wasm_version and wasm_sha384 from your
  // server's /auth/token endpoint and pass expectedHash for integrity checking.
  console.log('Loading WASM...');
  await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });
  console.log('WASM loaded.\n');

  // ── Step 2: Create client ──────────────────────────────────────────────────
  // Three-credential triplet:
  //   apiKey        — organisation key from the Sigbash dashboard
  //   userKey       — user identifier within your organisation
  //   userSecretKey — user-only secret (never sent to the server)
  if (!process.env.SIGBASH_SECRET_KEY) {
    throw new Error('SIGBASH_SECRET_KEY environment variable is required and must be a strong secret');
  }
  const client = new SigbashClient({
    serverUrl:     'https://www.sigbash.com',
    apiKey:        process.env.SIGBASH_API_KEY    || 'your-api-key',
    userKey:       process.env.SIGBASH_USER_KEY   || 'alice',
    userSecretKey: process.env.SIGBASH_SECRET_KEY,
  });

  // ── Step 3: Define a policy ────────────────────────────────────────────────
  // Allow spending only when ALL outputs are <= 100,000 sats AND no more than
  // 3 times per rolling day.
  const policy = conditionConfigToPoetPolicy({
    logic: 'AND',
    conditions: [
      {
        type: 'OUTPUT_VALUE',
        selector: 'ALL',
        operator: 'LTE',
        value: 100_000,   // 0.001 BTC
      },
      {
        type: 'COUNT_BASED_CONSTRAINT',
        max_uses: 3,
        reset_interval: 'daily',
        reset_type: 'rolling',
      },
    ],
  });

  // ── Step 4: Register a key ─────────────────────────────────────────────────
  let keyId, p2trAddress, bip328Xpub;
  try {
    const result = await client.createKey({
      policy,
      network: 'signet',    // 'mainnet' | 'testnet' | 'signet'
      require2FA: false,
    });
    keyId = result.keyId;
    p2trAddress = result.p2trAddress;
    bip328Xpub  = result.bip328Xpub;

    console.log('Key registered!');
    console.log('  keyId:       ', keyId);
    console.log('  P2TR address:', p2trAddress);
    console.log('  BIP-328 xpub:', bip328Xpub);
    console.log();
    console.log('Fund this address with a UTXO on signet, then create a PSBT spending it.\n');
  } catch (err) {
    if (err instanceof KeyIndexExistsError) {
      console.log(`Key index 0 already exists. Use keyIndex: ${err.nextAvailableIndex} to create another.`);
      return;
    }
    if (err instanceof PolicyCompileError) {
      console.error('Policy rejected by server:');
      err.compilationTrace.forEach((line, i) => console.error(`  ${i + 1}. ${line}`));
      return;
    }
    throw err;
  }

  // ── Step 5: Retrieve key material ─────────────────────────────────────────
  // kmcJSON is the encrypted key material container — pass it directly to signPSBT.
  const { kmcJSON } = await client.getKey(keyId);
  console.log('Key material retrieved.\n');

  // ── Step 6: Sign a PSBT ───────────────────────────────────────────────────
  // Replace this with a real base64-encoded PSBT spending the funded address.
  const psbtBase64 = process.env.SIGBASH_TEST_PSBT;
  if (!psbtBase64) {
    console.log('Set SIGBASH_TEST_PSBT env var to a base64 PSBT to test signing.');
    return;
  }

  const result = await client.signPSBT({
    keyId,
    psbtBase64,
    kmcJSON,
    network: 'signet',
    progressCallback: (step, msg) => process.stdout.write(`  [${step}] ${msg}\n`),
  });

  if (result.success) {
    console.log('\nSigning succeeded!');
    console.log('  txHex:           ', result.txHex);
    console.log('  satisfiedClause: ', result.satisfiedClause);
  } else {
    console.error('\nSigning failed:', result.error);
  }
}

main().catch(err => {
  console.error('Unexpected error:', err.message);
  process.exit(1);
});
