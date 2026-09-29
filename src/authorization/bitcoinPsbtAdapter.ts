/**
 * The authorization subject adapter for `bitcoin_psbt` — the subject kind
 * whose raw bytes are a BIP-174 PSBT. It carries the two halves of the
 * subject check's transaction-facing work:
 *
 *  - checkVerifiable: the posture-shape gate, mirroring the WASM lane's
 *    lfValidateAuthorizationPostureShape (refuse, never fail open): every
 *    input's declared sighash posture in {0x00, 0x01, 0x81}, every position
 *    resolvable, an ACP position taproot-shaped with a witnessUtxo, and a
 *    multi-position session never completing on an ACP position.
 *  - rederiveCompletingEHat: stage 2 — the completing position's lane
 *    sighash recomputed from the RAW PSBT per the envelope's posture
 *    disclosure, Q from the prevout output key, R' from the client-held
 *    salt, sigma all-zero (the lane exchanges no nonces), e_hat = e' + beta.
 */

import {
  authzDeriveRNonceX,
  authzEHat,
  authzPrevoutQ,
  authzSighashAcpKeyPath,
  authzSighashAcpTapscript,
  authzSighashKeyPath,
  authzSighashTapscriptKeyPath,
  AuthzTxInput,
  AuthzTxOutput,
} from '../contracts/authorizationSubject';
import {
  AuthorizationSubjectAdapter,
  getAuthorizationAdapter,
  registerAuthorizationAdapter,
} from './adapterRegistry';
import { completingPositionOf } from './envelope';
import { parseTransaction, parsePsbtBytes, ParsedPsbt, ParsedTx, tapLeafHash } from './psbt';

export const AUTHORIZATION_SUBJECT_KIND_BITCOIN_PSBT = 'bitcoin_psbt';

/** The sighash postures the lane accepts (the set the circuit pins). */
const ACCEPTED_POSTURES = new Set([0x00, 0x01, 0x81]);

function fail(message: string): never {
  throw new Error(message);
}

function isP2TR(scriptPubKey: Uint8Array): boolean {
  return scriptPubKey.length === 34 && scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20;
}

/** Resolve one input's prevout (witnessUtxo, else the non-witness tx's output). */
function resolvePrevout(psbt: ParsedPsbt, index: number): { value: number; scriptPubKey: Uint8Array } {
  const input = psbt.inputs[index];
  if (input?.witnessUtxo) return input.witnessUtxo;
  if (input?.nonWitnessUtxo) {
    const prevTx: ParsedTx = parseTransaction(input.nonWitnessUtxo);
    const vout = psbt.unsignedTx.inputs[index].vout;
    if (vout < prevTx.outputs.length) {
      return prevTx.outputs[vout];
    }
    fail(`position ${index}'s non-witness utxo does not contain its prevout`);
  }
  fail(`position ${index} has no resolvable prevout (witnessUtxo or nonWitnessUtxo)`);
}

// Local alias so the import below reads as a single pull from the parser.

function buildAdapterInputs(psbt: ParsedPsbt): AuthzTxInput[] {
  return psbt.unsignedTx.inputs.map((txIn, i) => {
    const prevout = resolvePrevout(psbt, i);
    return {
      txid: txIn.txid,
      vout: txIn.vout,
      sequence: txIn.sequence,
      amount: prevout.value,
      scriptPubKey: prevout.scriptPubKey,
    };
  });
}

function buildAdapterOutputs(psbt: ParsedPsbt): AuthzTxOutput[] {
  return psbt.unsignedTx.outputs.map(o => ({
    value: o.value,
    scriptPubKey: o.scriptPubKey,
  }));
}

export const bitcoinPsbtAdapter: AuthorizationSubjectAdapter = {
  subjectKind: AUTHORIZATION_SUBJECT_KIND_BITCOIN_PSBT,
  checkVerifiable(rawSubject) {
    const psbt = parsePsbtBytes(rawSubject);
    const inputs = psbt.inputs;
    if (inputs.length === 0) fail('the session has no positions');
    if (inputs.length !== psbt.unsignedTx.inputs.length) {
      fail('the PSBT input map does not cover every transaction input');
    }
    inputs.forEach((input, i) => {
      const posture = input.sighashType ?? 0x00;
      if (!ACCEPTED_POSTURES.has(posture)) {
        fail(`position ${i} declares sighash posture 0x${posture.toString(16)} outside the accepted set {0x00, 0x01, 0x81}`);
      }
      const prevout = resolvePrevout(psbt, i);
      if (posture === 0x81) {
        if (!isP2TR(prevout.scriptPubKey)) {
          fail(`position ${i} declares ANYONECANPAY but its prevout is not P2TR — the ACP canonical encoding is taproot-shaped`);
        }
        if (!input.witnessUtxo) {
          fail(`ANYONECANPAY position ${i} has no witnessUtxo — the ACP canonical encoding reads the prevout from it`);
        }
        if (i === inputs.length - 1 && inputs.length > 1) {
          fail('multi-position session completes on an ANYONECANPAY position — the completing proof must bind the whole transaction via the non-ACP preimage');
        }
      }
    });
  },
  rederiveCompletingEHat(rawSubject, envelope, salt) {
    const psbt = parsePsbtBytes(rawSubject);
    const completing = completingPositionOf(envelope);
    const position = envelope.completingPosition;
    const posture = completing.posture;
    const effectiveIsAcp = posture.hashType === 0x81;
    if (posture.isAcp !== effectiveIsAcp) {
      fail(`the completing position's disclosure disagrees with its encoded posture 0x${posture.hashType.toString(16)}`);
    }

    const adapterInputs = buildAdapterInputs(psbt);
    const adapterOutputs = buildAdapterOutputs(psbt);
    if (position < 0 || position >= adapterInputs.length) {
      fail(`the completing position ${position} is outside the PSBT`);
    }

    // The tapscript branch binds the position's first tap leaf, exactly as
    // the WASM export selects it; the disclosed leaf hash must match the
    // PSBT's own leaf when both are resolvable.
    const tapLeaf = psbt.inputs[position]?.tapLeafScripts[0];
    let leafHash: Uint8Array | undefined;
    if (posture.muxBranch === 'tapscript') {
      if (!posture.leafHash && !tapLeaf) {
        fail('the completing position declares the tapscript branch but no leaf is resolvable');
      }
      const disclosed = posture.leafHash;
      if (tapLeaf && disclosed &&
          !tapLeafHash(tapLeaf).every((b, i) => b === disclosed[i])) {
        fail("the completing position's disclosed leaf hash does not match its PSBT tap leaf");
      }
      leafHash = disclosed ?? (tapLeaf ? tapLeafHash(tapLeaf) : undefined);
    } else if (tapLeaf) {
      // The export sets the tapscript branch whenever the input carries a
      // leaf, so a key-path disclosure alongside a tap leaf is a shape the
      // lane never produces.
      fail('the completing position carries a tap leaf but discloses the key-path branch');
    }

    if (posture.muxBranch === 'tapscript' && !leafHash) {
      fail('the completing position declares the tapscript branch but no leaf is resolvable');
    }
    const sighash = effectiveIsAcp
      ? (leafHash
        ? authzSighashAcpTapscript(adapterInputs, adapterOutputs, position, leafHash)
        : authzSighashAcpKeyPath(adapterInputs, adapterOutputs, position))
      : (leafHash
        ? authzSighashTapscriptKeyPath(adapterInputs, adapterOutputs, position, leafHash)
        : authzSighashKeyPath(adapterInputs, adapterOutputs, position));

    const qX = authzPrevoutQ(adapterInputs[position].scriptPubKey);
    const rX = authzDeriveRNonceX(salt, envelope.sessionId);
    // The zero sigma: the authorization lane exchanges no nonces.
    return authzEHat(rX, qX, sighash, new Uint8Array(32));
  },
};

/** Register the adapter if no adapter for the kind exists yet. */
export function ensureBitcoinPsbtAdapterRegistered(): void {
  if (!getAuthorizationAdapter(bitcoinPsbtAdapter.subjectKind)) {
    registerAuthorizationAdapter(bitcoinPsbtAdapter);
  }
}
