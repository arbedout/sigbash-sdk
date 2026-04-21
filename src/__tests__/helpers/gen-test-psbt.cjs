#!/usr/bin/env node
'use strict';

/**
 * gen-test-psbt.cjs
 *
 * Constructs a minimal unsigned PSBT that spends a single P2TR UTXO and sends
 * the proceeds (minus fee) back to the same script.  Used by bitcoin-signet-helper.ts
 * to build test PSBTs for the signPSBT integration tests.
 *
 * Usage: node gen-test-psbt.cjs <txid> <vout> <valueSats> <scriptPubKeyHex>
 * Output: base64-encoded PSBT on stdout
 */

const { Psbt, networks } = require('bitcoinjs-lib');

const [txid, voutStr, valueSatsStr, scriptPubKeyHex] = process.argv.slice(2);

if (!txid || voutStr === undefined || !valueSatsStr || !scriptPubKeyHex) {
  process.stderr.write(
    'Usage: gen-test-psbt.cjs <txid> <vout> <valueSats> <scriptPubKeyHex>\n'
  );
  process.exit(1);
}

const vout = parseInt(voutStr, 10);
const valueSats = parseInt(valueSatsStr, 10);
const FEE_SATS = 1000;
const outputSats = valueSats - FEE_SATS;

if (outputSats <= 0) {
  process.stderr.write(`valueSats (${valueSats}) is too small to cover fee (${FEE_SATS})\n`);
  process.exit(1);
}

// Signet uses the same chaincfg params as testnet
const network = networks.testnet;

const scriptPubKeyBuf = Buffer.from(scriptPubKeyHex, 'hex');

const psbt = new Psbt({ network });

psbt.addInput({
  hash: txid,
  index: vout,
  witnessUtxo: {
    value: BigInt(valueSats),
    script: scriptPubKeyBuf,
  },
});

// Send back to the same scriptPubKey (self-payment, no change needed for test)
psbt.addOutput({
  script: scriptPubKeyBuf,
  value: BigInt(outputSats),
});

process.stdout.write(psbt.toBase64() + '\n');
