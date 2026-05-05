/**
 * Bitcoin Signet helper for SDK integration tests.
 *
 * Uses `docker exec` to interact with the local bitcoin-signet-instance container
 * and the gen-test-psbt.cjs helper to construct PSBTs.
 *
 * This file is excluded from Jest discovery by testPathIgnorePatterns.
 */

import { execSync } from 'child_process';
import * as path from 'path';

const CONTAINER = 'bitcoin-signet-instance';
const MASTER_WALLET = 'testing_master';
const SDK_WALLET = 'sdk_integration_test';
const GEN_PSBT_SCRIPT = path.resolve(__dirname, 'gen-test-psbt.cjs');

function btcCli(cmd: string, wallet?: string): string {
  const walletArg = wallet ? `-rpcwallet=${wallet} ` : '';
  return execSync(
    `docker exec ${CONTAINER} bitcoin-cli -signet ${walletArg}${cmd}`,
    { encoding: 'utf-8' }
  ).trim();
}

function btcCliJson<T>(cmd: string, wallet?: string): T {
  return JSON.parse(btcCli(cmd, wallet)) as T;
}

/**
 * Given a BIP-328 xpub (e.g. "[fp]tpubXXX"), derive the P2TR address at
 * child index 0, fund it from the testing_master wallet, and return the
 * UTXO info needed to build a PSBT.
 *
 * Requires the bitcoin-signet-instance Docker container to be running and
 * the testing_master wallet to have sufficient funds.
 */
export function fundXpubAndGetUtxo(bip328Xpub: string, amountBtc = 0.00002): {
  txid: string;
  vout: number;
  valueSats: number;
  scriptPubKeyHex: string;
  address: string;
} {
  // 1. Compute descriptor with checksum
  const descriptor = `tr(${bip328Xpub}/*)`;
  // Shell-escape the descriptor: wrap in single quotes and escape any single quotes inside
  const escapedDesc = descriptor.replace(/'/g, "'\\''");
  const descInfo = btcCliJson<{ descriptor: string }>(`getdescriptorinfo '${escapedDesc}'`);
  const descWithChecksum = descInfo.descriptor;

  // 2. Derive the P2TR address at index 0
  const escapedDescCs = descWithChecksum.replace(/'/g, "'\\''");
  const addresses = btcCliJson<string[]>(`deriveaddresses '${escapedDescCs}' '[0,0]'`);
  const address = addresses[0];

  // 3. Get scriptPubKey for this address
  const addrInfo = btcCliJson<{ scriptPubKey: string }>(
    `getaddressinfo ${address}`,
    MASTER_WALLET,
  );
  const scriptPubKeyHex = addrInfo.scriptPubKey;

  // 4. Fund from master wallet
  const rawTxid = btcCli(`sendtoaddress ${address} ${amountBtc.toFixed(8)}`, MASTER_WALLET);
  const txid = rawTxid.trim();

  // 5. Generate 1 block to confirm (mine to an arbitrary address in master wallet)
  const mineAddr = btcCli(`getnewaddress "mine" "bech32m"`, MASTER_WALLET);
  btcCli(`generatetoaddress 1 ${mineAddr}`);

  // 6. Find which vout went to our address
  const rawTx = btcCliJson<{
    vout: Array<{ n: number; value: number; scriptPubKey: { hex: string; address?: string } }>;
  }>(`getrawtransaction ${txid} true`);

  const outputIndex = rawTx.vout.findIndex(
    (out) => out.scriptPubKey.hex === scriptPubKeyHex,
  );
  if (outputIndex === -1) {
    throw new Error(`Could not find output for address ${address} in tx ${txid}`);
  }
  const outputEntry = rawTx.vout[outputIndex];
  const valueSats = Math.round(outputEntry.value * 1e8);

  return { txid, vout: outputIndex, valueSats, scriptPubKeyHex, address };
}

/**
 * Build a PSBT base64 string from a funded UTXO using gen-test-psbt.cjs.
 */
export function buildPsbtFromUtxo(utxo: {
  txid: string;
  vout: number;
  valueSats: number;
  scriptPubKeyHex: string;
}): string {
  const output = execSync(
    `node "${GEN_PSBT_SCRIPT}" "${utxo.txid}" "${utxo.vout}" "${utxo.valueSats}" "${utxo.scriptPubKeyHex}"`,
    { encoding: 'utf-8' },
  ).trim();
  return output;
}

/**
 * Mine one block to the master wallet (to confirm pending transactions).
 */
export function mineBlock(): void {
  const mineAddr = btcCli(`getnewaddress "mine" "bech32m"`, MASTER_WALLET);
  btcCli(`generatetoaddress 1 ${mineAddr}`);
}

/**
 * Broadcast a raw transaction hex and return the resulting txid.
 */
export function sendRawTx(txHex: string): string {
  return btcCli(`sendrawtransaction ${txHex}`);
}

/**
 * Check whether the bitcoin-signet-instance Docker container is running.
 */
export function isBitcoinContainerRunning(): boolean {
  try {
    const status = execSync(
      `docker ps --filter "name=${CONTAINER}" --format "{{.Status}}"`,
      { encoding: 'utf-8' },
    ).trim();
    return status.includes('Up');
  } catch {
    return false;
  }
}
