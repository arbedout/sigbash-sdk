import { SigbashClient } from './SigbashClient';
import type { Network } from './types';

/**
 * Minimal structural interface for a Bitcoin transaction that is compatible
 * with @arkade-os/ts-sdk's Transaction class.  Callers working with ts-sdk
 * pass a `Transaction` instance and TypeScript's structural typing ensures
 * compatibility without requiring ts-sdk as a direct SDK dependency.
 */
export interface ArkadeTransaction {
  toPSBT(): Uint8Array;
}

/**
 * Minimal structural interface for a MuSig2 tree signer session, compatible
 * with @arkade-os/ts-sdk's SignerSession interface (signingSession.ts).
 *
 * Method signatures exactly mirror the real SignerSession but use `any` for
 * the complex ts-sdk internal types (TxTree, TreeNonces, TreePartialSigs)
 * that are not available without ts-sdk as a direct dependency.  TypeScript
 * bivariant method checking ensures structural compatibility at call sites.
 */
export interface ArkadeSignerSession {
  getPublicKey(): Promise<Uint8Array>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  init(tree: any, scriptRoot: Uint8Array, rootInputAmount: bigint): Promise<void>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getNonces(): Promise<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  aggregatedNonces(txid: string, noncesByPubkey: any): Promise<{ hasAllNonces: boolean }>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  sign(): Promise<any>;
}

/**
 * Ark Labs signing context injected before wallet operations that trigger
 * MATCH_ARK_INTENT or MATCH_ARK_COLLABORATIVE_EXIT policy evaluation.
 */
export interface ArkadeContext {
  /** JSON-encoded Ark Labs register message (canonical field order required). */
  registerMessageJson: string;
  /** Per-input array of tapscript branch paths from the vtxo taptree. */
  vtxoTaprootTrees: string[][];
}

// Ark-proprietary VtxoTaprootTree PSBT unknown field key: 0xDE + "taptree".
// Present on input[1+] of every Ark register-intent PSBT; never on spending PSBTs.
const ARK_TAPTREE_KEY = Buffer.from([0xde, 0x74, 0x61, 0x70, 0x74, 0x72, 0x65, 0x65]);

export class SigbashArkadeSigningError extends Error {
  /**
   * True when the throw represents an expected policy *outcome* (the PSBT simply
   * does not satisfy the key's policy) rather than an infrastructure failure.
   * Informational errors carry no multi-frame stack: they routinely surface from
   * background flows (e.g. Ark periodic-settle renewals on a narrow
   * CHECKPOINT/FORFEIT-clause key, which can't sign a bare register-intent), and
   * a full stack trace there is just noise. The error is still thrown so callers
   * (and negative tests) observe a rejection.
   */
  readonly informational: boolean;

  constructor(message: string, informational = false) {
    super(message);
    this.name = 'SigbashArkadeSigningError';
    this.informational = informational;
    if (informational) {
      // Collapse the stack to the header line. Callers that log `err.stack`
      // (the ts-sdk periodic-settle handler does) then emit a single clean line
      // instead of a stack dump for a benign, expected outcome.
      this.stack = `${this.name}: ${message}`;
    }
  }
}

/**
 * Recognise the messages the WASM/server returns when a PSBT legitimately does
 * not satisfy the policy (as opposed to a crash, parse error, or network
 * failure). These are expected outcomes, not bugs.
 */
function isPolicyOutcomeMessage(message: string): boolean {
  return (
    message.includes('Policy not satisfied') ||
    message.includes('policy evaluation failed')
  );
}

/**
 * Identity implementation that bridges @arkade-os/ts-sdk wallets to the
 * Sigbash co-signing platform.  Fulfils the ts-sdk Identity interface via
 * TypeScript structural typing — no ts-sdk package dependency is required.
 *
 * Usage:
 * ```typescript
 * import { Transaction } from '@arkade-os/ts-sdk/src/utils/transaction';
 * import { TreeSignerSession } from '@arkade-os/ts-sdk/src/tree/signingSession';
 *
 * const identity = new SigbashArkadeIdentity(
 *   sigbashClient, keyId, kmcJSON,
 *   Buffer.from(aggregatePubKeyHex, 'hex'),
 *   'signet',
 *   () => TreeSignerSession.random(),
 *   (bytes) => Transaction.fromPSBT(bytes),
 * );
 * ```
 *
 * For intent / collaborative-exit flows, inject context before calling the
 * wallet operation:
 * ```typescript
 * await identity.setArkadeContext({ registerMessageJson, vtxoTaprootTrees });
 * await wallet.send({ address: destination, amount: 50_000n });
 * // Context is automatically cleared after sign() returns.
 * ```
 *
 * Policy composition requirement: a single `wallet.send()` also signs the
 * intermediate checkpoint tx, and a single `ramps.offboard()` also signs a
 * forfeit-shaped settlement tx — both with the single-use ArkadeContext already
 * consumed by the arkTx sign. The signer no longer waves these intermediate
 * shapes through on structure alone, so the key's policy MUST compose the
 * dedicated infra atom alongside the intent/exit atom via OR, e.g.
 * `OR(MATCH_ARK_INTENT{...}, MATCH_ARK_CHECKPOINT{operator_pubkey, csv_timeout, max_fee})`
 * for sends and
 * `OR(MATCH_ARK_COLLABORATIVE_EXIT{...}, MATCH_ARK_FORFEIT{operator_pubkey, forfeit_script_pubkey, max_fee})`
 * for offboards. The checkpoint `csv_timeout` must equal the operator's actual
 * unroll delay and the forfeit `forfeit_script_pubkey` the operator forfeit script
 * (both from arkd `getInfo()`). Omitting the infra atom makes legitimate
 * sends/offboards fail to co-sign the intermediate tx.
 */
export class SigbashArkadeIdentity<T extends ArkadeTransaction = ArkadeTransaction> {
  private arkadeCtx: ArkadeContext | null = null;
  /** Mutex: resolves to true when no signing is in progress; held during sign(). */
  private signingLock: Promise<void> = Promise.resolve();
  /**
   * True while setArkadeContext() has set a context that has not yet been
   * consumed by a foreground (non-intent) sign(). Decoupled from the signingLock
   * mutex: intent-proof sign()s (background vtxo-renewal register-intents) do NOT
   * clear it, so they can no longer strip the foreground ArkadeContext. Only a
   * consuming (non-intent) sign() — the intended arkTx — clears it.
   */
  private _contextPending = false;
  /**
   * Incremented on every sign() call.  Read by investigation tests to verify
   * how many times identity.sign() fires during wallet.send() / ramps.onboard().
   * Remove together with the console.log below once investigations are complete.
   */
  _signCount = 0;
  /**
   * Incremented only for intent-proof sign() calls (input[0].witnessUtxo.amount === 0n).
   * Intent proofs (register-intent PSBTs) are allowed unconditionally by WASM and do
   * not consume the ArkadeContext.  Tests can subtract this from _signCount to get
   * the count of policy-gated sign() calls (e.g. arkTx, real spending PSBTs).
   */
  _intentProofSignCount = 0;

  constructor(
    private readonly client: SigbashClient,
    private readonly keyId: string,
    private readonly kmcJSON: string,
    /** 33-byte compressed aggregate public key. */
    private readonly aggregatePubkey: Uint8Array,
    private readonly network: Network = 'signet',
    /**
     * Factory for MuSig2 tree signer sessions used during vtxo tree
     * co-signing.  Typical usage:
     *   import { TreeSignerSession } from '@arkade-os/ts-sdk/src/tree/signingSession';
     *   () => TreeSignerSession.random()
     */
    private readonly signerSessionFactory: () => ArkadeSignerSession,
    /**
     * Factory that deserialises a signed PSBT back into a Transaction object.
     * Typical usage:
     *   import { Transaction } from '@arkade-os/ts-sdk/src/utils/transaction';
     *   (bytes) => Transaction.fromPSBT(bytes)
     */
    private readonly txFromPSBT: (bytes: Uint8Array) => T,
  ) {}

  /**
   * Pre-inject Ark Labs signing context before calling wallet.send() or
   * ramps.offboard() for intent / collaborative-exit flows.
   * Automatically cleared after each sign() call regardless of outcome.
   *
   * Awaiting this method guarantees that any sign() calls already in the queue
   * drain before the context is set, and that subsequent sign() calls block until
   * the intended wallet operation's sign() runs and consumes the context.
   * This prevents background vtxo renewal calls from stealing the context.
   */
  async setArkadeContext(ctx: ArkadeContext | null): Promise<void> {
    if (ctx === null) {
      this.arkadeCtx = null;
      this._contextPending = false;
      return;
    }
    // Drain any in-flight sign() so the context is set with nothing signing, then
    // arm the pending flag. The flag is decoupled from the signingLock mutex:
    // only a consuming (non-intent) sign() clears it, so a background renewal's
    // intent-proof sign()s cannot steal the context from the foreground arkTx.
    await this.signingLock;
    this.arkadeCtx = ctx;
    this._contextPending = true;
  }

  async xOnlyPublicKey(): Promise<Uint8Array> {
    return this.aggregatePubkey.slice(1); // strip 02/03 prefix → 32-byte x-only
  }

  async compressedPublicKey(): Promise<Uint8Array> {
    return this.aggregatePubkey;
  }

  /** Participates in MuSig2 vtxo tree co-signing during settlement. */
  signerSession(): ArkadeSignerSession {
    return this.signerSessionFactory();
  }

  /**
   * Returns true while setArkadeContext() has set a context that has not yet
   * been consumed by sign().  VtxoManager uses this to skip automatic renewal
   * attempts during the window between setArkadeContext() and the intended
   * wallet.send() / ramps.offboard() signing call, preventing background
   * settle operations from stealing the context.
   */
  hasPendingContext(): boolean {
    return this._contextPending;
  }

  async signMessage(
    _message: Uint8Array,
    _type: 'schnorr' | 'ecdsa',
  ): Promise<Uint8Array> {
    throw new SigbashArkadeSigningError(
      'SigbashArkadeIdentity does not support signMessage; use sign(tx) via wallet operations',
    );
  }

  async sign(tx: T, _inputIndexes?: number[]): Promise<T> {
    // Classify the PSBT before acquiring the lock (pure, no await). An Ark
    // register-intent proof is identified by two Ark-specific conditions:
    //   1. input[0].witnessUtxo.amount === 0n  (BIP-322 toSpend fake)
    //   2. the raw PSBT bytes contain key 0xDE+"taptree"  (Ark VtxoTaprootTree field)
    // No generic spending PSBT carries the 0xDE taptree unknown field. Intent
    // proofs are authorized by WASM on their own merits and must NOT consume the
    // ArkadeContext — it is reserved for the foreground arkTx.
    // input[0] keeps its tapLeafScript so arkd finalizes it along the tapscript
    // path (intent/proof.go FinalizeAndExtract copies input[1]'s unknowns onto
    // input[0], appends the operator fake sig, finalizes via FinalizeVtxoScript).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const input0 = (tx as any).getInput?.(0);
    const psbtBytes = tx.toPSBT();
    const isIntentProof = input0?.witnessUtxo?.amount === 0n &&
      Buffer.from(psbtBytes).indexOf(ARK_TAPTREE_KEY) !== -1;

    // Serialize concurrent sign() calls (mutex) so a background wallet settle
    // cannot interfere with the sign_with_hash_auth pre-flight of a foreground sign.
    let releaseLock!: () => void;
    const prevLock = this.signingLock;
    this.signingLock = new Promise<void>((resolve) => { releaseLock = resolve; });
    await prevLock;

    // A consuming (non-intent) sign is the intended foreground consumer: clear the
    // pending-context flag. Intent-proof signs skip this — they neither consume nor
    // clear the context, so a background renewal's register-intent proofs can no
    // longer strip the ArkadeContext from the foreground arkTx. (Full protection
    // against a background *non-intent* sign interleaving still relies on the
    // caller invoking setArkadeContext() synchronously before the foreground
    // operation, since the upstream VtxoManager does not consult hasPendingContext().)
    if (!isIntentProof) {
      this._contextPending = false;
    }

    try {
      const psbtBase64 = Buffer.from(psbtBytes).toString('base64');
      // Temporary investigation log — remove after confirming FORFEIT/CHECKPOINT call paths.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const inputCount = (tx as any).inputsLength ?? '?';
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const outputCount = (tx as any).outputsLength ?? '?';
      ++this._signCount;
      if (isIntentProof) ++this._intentProofSignCount;
      console.log(
        `[SigbashArkadeIdentity.sign #${this._signCount}] ` +
        `inputs=${inputCount} outputs=${outputCount} ` +
        `intentProof=${isIntentProof} ` +
        `psbt=${psbtBase64.slice(0, 40)}...`,
      );

      // Consume context only for real spending PSBTs (non-intent-proofs).
      // Intent proofs pass undefined so WASM authorizes them on their own merits.
      const arkadeIntentContext = isIntentProof ? undefined : (this.arkadeCtx ?? undefined);
      if (!isIntentProof) {
        this.arkadeCtx = null; // clear before the async call to prevent bleed
      }

      const result = await this.client.signPSBT({
        keyId: this.keyId,
        psbtBase64,
        kmcJSON: this.kmcJSON,
        network: this.network,
        arkadeIntentContext,
        // Never pre-finalize intent proofs: arkd runs its own FinalizeAndExtract
        // (intent/proof.go), appending the operator's fake zero-sig before
        // assembling the witness from each input's TaprootScriptSpendSig.  If the
        // WASM populates FinalScriptWitness first, arkd's finalizer skips the input
        // (proof.go: "already finalized") and the operator slot of the N-of-N leaf
        // is never filled — yielding "PSBT cannot be extracted as it is incomplete".
        // The non-intent arkTx/checkpoint/forfeit paths already pass false.
        finalizePsbt: false,
      });

      if (!result.success) {
        const msg = result.error ?? 'Sigbash refused to sign';
        // A "Policy not satisfied" outcome is informational — throw without a
        // stack trace so a background renewal that hits it logs cleanly. A
        // genuine refusal / infra error keeps its full stack for debugging.
        throw new SigbashArkadeSigningError(msg, isPolicyOutcomeMessage(msg));
      }

      return this.txFromPSBT(Buffer.from(result.signedPSBT!, 'base64'));
    } finally {
      releaseLock();
    }
  }
}
