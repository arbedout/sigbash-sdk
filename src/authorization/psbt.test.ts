/**
 * The minimal BIP-174 reader, cross-checked against bitcoinjs-lib (a
 * dev-only dependency): whatever the reader extracts from a PSBT built by
 * the canonical library must agree field for field, and every malformed
 * shape must refuse.
 */

import { Psbt, Transaction } from 'bitcoinjs-lib';
import {
  parsePsbt,
  parsePsbtBytes,
  PsbtParseError,
  tapLeafHash,
} from './psbt';

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

/** A taproot key-path PSBT: one P2TR input with a witness utxo and a
 * declared SIGHASH_DEFAULT, one P2TR output. */
function buildTaprootPsbt(): Psbt {
  const psbt = new Psbt();
  psbt.addInput({
    hash: Buffer.from('aec97b6b57e5ac54912a6c9478d4e647216e39e4ffac99a5d2541ce447001926', 'hex').reverse(),
    index: 0,
    sequence: 0xfffffffe,
    witnessUtxo: {
      script: Buffer.from('5120' + '212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4', 'hex'),
      value: 25000,
    },
  });
  // SIGHASH_ALL for the cross-check: bitcoinjs-lib/bip174 refuse to encode
  // the SIGHASH_DEFAULT (0x00) posture, so that path is covered by the
  // hand-built fixture PSBT in the verify suite.
  psbt.updateInput(0, { sighashType: 1 });
  psbt.addOutput({
    script: Buffer.from('5120' + '9b8c8d2f22a3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9', 'hex'),
    value: 20000,
  });
  return psbt;
}

describe('minimal BIP-174 reader', () => {
  it('agrees with bitcoinjs-lib on the unsigned transaction', () => {
    const psbt = buildTaprootPsbt();
    const parsed = parsePsbt(psbt.toBase64());
    // extractTransaction() demands a finalized PSBT; the unsigned
    // transaction in the global map is the comparison point.
    const canonical = (psbt.data.globalMap.unsignedTx as { tx: Transaction }).tx;

    expect(parsed.unsignedTx.version).toBe(canonical.version);
    expect(parsed.unsignedTx.lockTime).toBe(canonical.locktime);
    expect(parsed.unsignedTx.inputs).toHaveLength(canonical.ins.length);
    expect(parsed.unsignedTx.outputs).toHaveLength(canonical.outs.length);
    parsed.unsignedTx.inputs.forEach((input, i) => {
      expect(Buffer.from(input.txid)).toEqual(Buffer.from(canonical.ins[i].hash));
      expect(input.vout).toBe(canonical.ins[i].index);
      expect(input.sequence).toBe(canonical.ins[i].sequence);
    });
    parsed.unsignedTx.outputs.forEach((output, i) => {
      expect(output.value).toBe(Number(canonical.outs[i].value));
      expect(Buffer.from(output.scriptPubKey)).toEqual(Buffer.from(canonical.outs[i].script));
    });
  });

  it('agrees with bitcoinjs-lib on the input map: utxo, posture, leaves', () => {
    const psbt = buildTaprootPsbt();
    const parsed = parsePsbt(psbt.toBase64());
    const data = psbt.data.inputs[0];

    expect(parsed.inputs).toHaveLength(1);
    expect(parsed.inputs[0].witnessUtxo?.value).toBe(25000);
    expect(Buffer.from(parsed.inputs[0].witnessUtxo!.scriptPubKey))
      .toEqual(Buffer.from(data.witnessUtxo!.script));
    expect(parsed.inputs[0].sighashType).toBe(0x01);
    expect(parsed.inputs[0].tapLeafScripts).toEqual([]);
  });

  it('round-trips raw bytes byte-exactly (the subject check re-reads what it received)', () => {
    const psbt = buildTaprootPsbt();
    const raw = Buffer.from(psbt.toHex(), 'hex');
    const parsed = parsePsbtBytes(Uint8Array.from(raw));
    expect(Buffer.from(parsed.raw)).toEqual(raw);
  });

  it('parses a tap leaf script and hashes it per BIP-341 deterministically', () => {
    const psbt = buildTaprootPsbt();
    const script = Buffer.from('20' + 'aa'.repeat(32) + 'ac', 'hex'); // x-only key check
    psbt.updateInput(0, {
      tapLeafScript: [{
        leafVersion: 0xc0,
        script,
        controlBlock: Buffer.from('c0' + 'bb'.repeat(32), 'hex'),
      }],
    });
    const parsed = parsePsbt(psbt.toBase64());
    const leaf = parsed.inputs[0].tapLeafScripts[0];
    expect(leaf.leafVersion).toBe(0xc0);
    expect(Buffer.from(leaf.script)).toEqual(script);
    // The key data (control block) keeps the leaf-version leading byte.
    expect(Buffer.from(leaf.controlBlock)).toEqual(
      Buffer.from('c0' + 'bb'.repeat(32), 'hex'));

    // The hash is a 32-byte digest, stable for the same leaf.
    expect(tapLeafHash(leaf).length).toBe(32);
    expect(tapLeafHash(leaf)).toEqual(tapLeafHash({ ...leaf }));
  });

  it('refuses malformed structures fail-closed', () => {
    const psbt = buildTaprootPsbt();
    const raw = Buffer.from(psbt.toHex(), 'hex');

    // Not a PSBT.
    expect(() => parsePsbtBytes(Uint8Array.from(Buffer.from('deadbeef', 'hex')))).toThrow(PsbtParseError);
    // Trailing bytes after the fee map.
    expect(() => parsePsbtBytes(Uint8Array.from(Buffer.concat([raw, Buffer.from([0x00])]))))
      .toThrow(PsbtParseError);
    // Truncated body.
    expect(() => parsePsbtBytes(Uint8Array.from(raw.slice(0, raw.length - 4)))).toThrow(PsbtParseError);
  });

  it('refuses a PSBT v2 (BIP-370) instead of misreading it', () => {
    const psbt = buildTaprootPsbt();
    const raw = Buffer.from(psbt.toHex(), 'hex');
    // Global layout: magic(5) keyLen(1) key(1) valueLen(1) value(tx) separator(1).
    // The global separator sits right after the unsigned-tx value.
    const separatorAt = 8 + raw[7];
    expect(raw[separatorAt]).toBe(0x00);
    // Splice a global version entry (0xfb, LE32 v2) before the separator.
    const versionEntry = Buffer.concat([
      Buffer.from([0x01, 0xfb]),
      Buffer.from([0x04, 0x02, 0x00, 0x00, 0x00]),
    ]);
    const mutated = Buffer.concat([
      raw.slice(0, separatorAt), versionEntry, raw.slice(separatorAt),
    ]);
    expect(() => parsePsbtBytes(Uint8Array.from(mutated))).toThrow(/version 2/);
  });

  it('accepts unknown keys per BIP-174 without consuming them', () => {
    const psbt = buildTaprootPsbt();
    const raw = Buffer.from(psbt.toHex(), 'hex');
    // Add a proprietary global key (0xfc) with a one-byte payload:
    // keylen(2), key fc01, valuelen(1), value 0x2a.
    const proprietary = Buffer.from([0x02, 0xfc, 0x01, 0x01, 0x2a]);
    const separatorAt = 8 + raw[7];
    const mutated = Buffer.concat([
      raw.slice(0, separatorAt), proprietary, raw.slice(separatorAt),
    ]);
    const parsed = parsePsbtBytes(Uint8Array.from(mutated));
    expect(parsed.unsignedTx.inputs).toHaveLength(1);
  });
});
