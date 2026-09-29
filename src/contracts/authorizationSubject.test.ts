/**
 * The authorization subject-binding mirror is asserted against the committed
 * golden vectors — the same bytes the Flask mirror and the wasm suite's
 * golden-vector log pin. Any drift here fails a test, never a proof.
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import {
  authzActionKey,
  authzBeta,
  authzBurnSetAggregate,
  authzDeriveRNonceX,
  authzEHat,
  authzEPrime,
  authzPinAggregate,
  authzPrevoutQ,
  authzScope,
  authzSighashAcpKeyPath,
  authzSighashAcpTapscript,
  authzSighashKeyPath,
  authzSighashTapscriptKeyPath,
  compactSize,
  hexToBytes,
  sha256Compress,
} from './authorizationSubject';
import { sha256 } from '@noble/hashes/sha256';

const VECTORS = JSON.parse(
  readFileSync(join(__dirname, 'vectors', 'contracts-v1.json'), 'utf8'),
).authorization_subject_binding_v1 as {
  r_nonce_salt_hex: string;
  r_nonce_session_hex: string;
  sigma_hex: string;
  txid_hex: string;
  input: { vout: number; sequence: number; amount: number };
  acp_input: { vout: number; sequence: number; amount: number };
  leaf_hash_hex: string;
  outputs: { value: number; script_pub_key_hex: string }[];
  r_nonce_x_hex: string;
  shapes: Record<string, {
    sighash_hex: string; q_hex: string; e_prime_hex: string; beta_hex: string; e_hat_hex: string;
  }>;
  carry_wrap: {
    salt_hex: string; r_nonce_x_hex: string; shape: string;
    e_prime_hex: string; beta_hex: string; e_hat_hex: string;
  };
  large_script_q: { script_len: number; q_hex: string };
  pin_aggregate_hex: string;
  burn_set_aggregate_hex: string;
};

function shapeScript(kind: 'segwit_native_v0' | 'p2sh_wrapped' | 'taproot_key_path'): Uint8Array {
  const head: Record<string, number[]> = {
    segwit_native_v0: [0x00, 0x14],
    p2sh_wrapped: [0xa9, 0x14],
    taproot_key_path: [0x51, 0x20],
  };
  const body = Array.from({ length: kind === 'taproot_key_path' ? 32 : 20 },
    (_, i) => (((i + 2) * 13 + 7) & 0xff));
  const tail = kind === 'p2sh_wrapped' ? [0x87] : [];
  return Uint8Array.from([...head[kind], ...body, ...tail]);
}

describe('authorization subject binding (golden vectors)', () => {
  const salt = hexToBytes(VECTORS.r_nonce_salt_hex);
  const sessionId = hexToBytes(VECTORS.r_nonce_session_hex);
  const sigma = hexToBytes(VECTORS.sigma_hex);
  const txid = hexToBytes(VECTORS.txid_hex);
  const leaf = hexToBytes(VECTORS.leaf_hash_hex);
  const outputs = VECTORS.outputs.map(o => ({
    value: o.value,
    scriptPubKey: hexToBytes(o.script_pub_key_hex),
  }));

  it('derives R_x exactly as the committed vector', () => {
    expect(authzDeriveRNonceX(salt, sessionId)).toEqual(hexToBytes(VECTORS.r_nonce_x_hex));
  });

  it.each([
    ['segwit_native_v0'],
    ['p2sh_wrapped'],
    ['taproot_key_path'],
  ] as const)('binds the %s shape through sighash, Q, e-prime, beta and e-hat', (name) => {
    const script = shapeScript(name);
    const inputs = [{
      txid, vout: VECTORS.input.vout, sequence: VECTORS.input.sequence,
      amount: VECTORS.input.amount, scriptPubKey: script,
    }];
    const expected = VECTORS.shapes[name];
    const sighash = authzSighashKeyPath(inputs, outputs, 0);
    expect(sighash).toEqual(hexToBytes(expected.sighash_hex));
    const q = authzPrevoutQ(script);
    expect(q).toEqual(hexToBytes(expected.q_hex));
    expect(authzEPrime(hexToBytes(VECTORS.r_nonce_x_hex), q, sighash))
      .toEqual(hexToBytes(expected.e_prime_hex));
    expect(authzBeta(sighash, sigma)).toEqual(hexToBytes(expected.beta_hex));
    expect(authzEHat(hexToBytes(VECTORS.r_nonce_x_hex), q, sighash, sigma))
      .toEqual(hexToBytes(expected.e_hat_hex));
  });

  it('binds the tapscript shape through the leaf-hash extension', () => {
    const script = shapeScript('taproot_key_path');
    const inputs = [{
      txid, vout: VECTORS.input.vout, sequence: VECTORS.input.sequence,
      amount: VECTORS.input.amount, scriptPubKey: script,
    }];
    const sighash = authzSighashTapscriptKeyPath(inputs, outputs, 0, leaf);
    expect(sighash).toEqual(hexToBytes(VECTORS.shapes.taproot_script_path.sighash_hex));
    expect(authzEHat(hexToBytes(VECTORS.r_nonce_x_hex), authzPrevoutQ(script), sighash, sigma))
      .toEqual(hexToBytes(VECTORS.shapes.taproot_script_path.e_hat_hex));
  });

  it('binds both ACP shapes', () => {
    const script = shapeScript('taproot_key_path');
    const acpInputs = [{
      txid, vout: VECTORS.acp_input.vout, sequence: VECTORS.acp_input.sequence,
      amount: VECTORS.acp_input.amount, scriptPubKey: script,
    }];
    const keyPath = authzSighashAcpKeyPath(acpInputs, outputs, 0);
    expect(keyPath).toEqual(hexToBytes(VECTORS.shapes.acp_taproot.sighash_hex));
    const scriptPath = authzSighashAcpTapscript(acpInputs, outputs, 0, leaf);
    expect(scriptPath).toEqual(hexToBytes(VECTORS.shapes.acp_taproot_script_path.sighash_hex));
  });

  it('wraps the carry fixture exactly as the in-circuit adder does', () => {
    const wrap = VECTORS.carry_wrap;
    const script = shapeScript('taproot_key_path');
    const inputs = [{
      txid, vout: VECTORS.input.vout, sequence: VECTORS.input.sequence,
      amount: VECTORS.input.amount, scriptPubKey: script,
    }];
    const r = authzDeriveRNonceX(hexToBytes(wrap.salt_hex), sessionId);
    expect(r).toEqual(hexToBytes(wrap.r_nonce_x_hex));
    const sighash = authzSighashKeyPath(inputs, outputs, 0);
    const q = authzPrevoutQ(script);
    expect(authzEPrime(r, q, sighash)).toEqual(hexToBytes(wrap.e_prime_hex));
    expect(authzBeta(sighash, sigma)).toEqual(hexToBytes(wrap.beta_hex));
    // The committed fixture must genuinely wrap — the sum exceeds 2^256 and
    // the wrapped value is the binding.
    const total =
      BigInt('0x' + wrap.e_prime_hex) + BigInt('0x' + wrap.beta_hex);
    expect(total >= (1n << 256n)).toBe(true);
    expect(authzEHat(r, q, sighash, sigma)).toEqual(hexToBytes(wrap.e_hat_hex));
  });

  it('uses the compact-size length prefix past the single-byte range', () => {
    const big = Uint8Array.from({ length: VECTORS.large_script_q.script_len },
      (_, i) => (i * 13 + 7) & 0xff);
    expect(compactSize(300)).toEqual(Uint8Array.from([0xfd, 0x2c, 0x01]));
    expect(authzPrevoutQ(big)).toEqual(hexToBytes(VECTORS.large_script_q.q_hex));
  });

  it('recomputes the pin aggregate', () => {
    const digest = (label: string) => sha256(new TextEncoder().encode(label));
    const pin = authzPinAggregate(
      sessionId,
      0,
      [{ eHat: digest('authz-golden-ehat-0'), positionMode: 0 }],
      [{ hashOutputsBlindedCommit: digest('authz-golden-chunk-0'), covenantWriteCommit: new Uint8Array(16) }],
      {
        hashOutputsBlindedCommitUnified: digest('authz-golden-hobc'),
        hinBlindedCommitUnified: digest('authz-golden-hin'),
        saltBlindedCommitUnified: digest('authz-golden-saltcommit'),
        polyCoeffsBlindedCommitUnified: digest('authz-golden-poly'),
        inputSetPolyProduct: Uint8Array.from([1, ...new Array(15).fill(0)]),
      },
    );
    expect(pin).toEqual(hexToBytes(VECTORS.pin_aggregate_hex));
  });

  it('recomputes the burn-set aggregate', () => {
    const digest = (label: string) => sha256(new TextEncoder().encode(label));
    const burn = authzBurnSetAggregate(
      sessionId,
      [{ positionIndex: 0, n0: digest('authz-golden-n0'), n1: digest('authz-golden-n1') }],
    );
    expect(burn).toEqual(hexToBytes(VECTORS.burn_set_aggregate_hex));
  });
});

describe('sha256Compress', () => {
  it('agrees with a full SHA-256 over a single padded block', () => {
    // The initial state plus one message block must equal the full digest.
    const msg = new TextEncoder().encode('sigbash compression check');
    const block = new Uint8Array(64);
    block.set(msg, 0);
    block[msg.length] = 0x80;
    const dv = new DataView(block.buffer);
    dv.setUint32(60, msg.length * 8, false);
    const state = Uint8Array.from([
      0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
      0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
      0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
      0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
    ]);
    expect(sha256Compress(state, block)).toEqual(sha256(msg));
  });
});

describe('scope and action key', () => {
  it('derives the server-shaped scope digest', () => {
    // Shape check only: the scope is server-derived, so the SDK recomputes
    // it for comparison against the signed artifact value.
    const scope = authzScope('org-credential-1', 3);
    expect(scope.length).toBe(32);
    expect(authzScope('org-credential-1', 3)).toEqual(scope);
    expect(authzScope('org-credential-2', 3)).not.toEqual(scope);
    expect(authzScope('org-credential-1', 4)).not.toEqual(scope);
  });

  it('builds the action key from the N0s of the burn echo', () => {
    const n0 = hexToBytes('aa'.repeat(32));
    const n1 = hexToBytes('bb'.repeat(32));
    expect(authzActionKey([n0])).toEqual(authzActionKey([n0]));
    expect(authzActionKey([n0])).not.toEqual(authzActionKey([n1]));
  });
});
