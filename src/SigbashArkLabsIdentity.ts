import { SigbashClient } from './SigbashClient';
import type { Network } from './types';

/**
 * Minimal structural interface for a Bitcoin transaction that is compatible
 * with @arkade-os/ts-sdk's Transaction class.  Callers working with ts-sdk
 * pass a `Transaction` instance and TypeScript's structural typing ensures
 * compatibility without requiring ts-sdk as a direct SDK dependency.
 */
export interface ArkLabsTransaction {
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
export interface ArkLabsSignerSession {
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
export interface ArkLabsContext {
  /** JSON-encoded Ark Labs register message (canonical field order required). */
  registerMessageJson: string;
  /** Per-input array of tapscript branch paths from the vtxo taptree. */
  vtxoTaprootTrees: string[][];
}

// Ark-proprietary VtxoTaprootTree PSBT unknown field key: 0xDE + "taptree".
// Present on input[1+] of every Ark register-intent PSBT; never on spending PSBTs.
const ARK_TAPTREE_KEY = Buffer.from([0xde, 0x74, 0x61, 0x70, 0x74, 0x72, 0x65, 0x65]);

export class SigbashArkLabsSigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SigbashArkLabsSigningError';
  }
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
 * const identity = new SigbashArkLabsIdentity(
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
 * await identity.setArkLabsContext({ registerMessageJson, vtxoTaprootTrees });
 * await wallet.send({ address: destination, amount: 50_000n });
 * // Context is automatically cleared after sign() returns.
 * ```
 */
export class SigbashArkLabsIdentity<T extends ArkLabsTransaction = ArkLabsTransaction> {
  private arkLabsCtx: ArkLabsContext | null = null;
  /** Mutex: resolves to true when no signing is in progress; held during sign(). */
  private signingLock: Promise<void> = Promise.resolve();
  /**
   * Non-null while a setArkLabsContext() call has set context and is waiting for
   * the first sign() to consume it.  sign() calls this to release the hold before
   * awaiting prevLock, preventing a deadlock between the context lock and the queue.
   */
  private _contextLockRelease: (() => void) | null = null;
  /**
   * Incremented on every sign() call.  Read by investigation tests to verify
   * how many times identity.sign() fires during wallet.send() / ramps.onboard().
   * Remove together with the console.log below once investigations are complete.
   */
  _signCount = 0;
  /**
   * Incremented only for intent-proof sign() calls (input[0].witnessUtxo.amount === 0n).
   * Intent proofs (register-intent PSBTs) are allowed unconditionally by WASM and do
   * not consume the ArkLabsContext.  Tests can subtract this from _signCount to get
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
    private readonly signerSessionFactory: () => ArkLabsSignerSession,
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
  async setArkLabsContext(ctx: ArkLabsContext | null): Promise<void> {
    if (ctx === null) {
      this.arkLabsCtx = null;
      return;
    }
    // 1. Drain all currently-queued sign() calls so we start with a clean queue.
    await this.signingLock;
    // 2. Set context while no sign() is running.
    this.arkLabsCtx = ctx;
    // 3. Insert a new pending lock that blocks ALL subsequent sign() calls until
    //    the intended sign() releases it via _contextLockRelease.
    let release!: () => void;
    this.signingLock = new Promise<void>((resolve) => {
      release = resolve;
      this._contextLockRelease = release;
    });
    // Do NOT release now — sign() releases it when it runs.
  }

  async xOnlyPublicKey(): Promise<Uint8Array> {
    return this.aggregatePubkey.slice(1); // strip 02/03 prefix → 32-byte x-only
  }

  async compressedPublicKey(): Promise<Uint8Array> {
    return this.aggregatePubkey;
  }

  /** Participates in MuSig2 vtxo tree co-signing during settlement. */
  signerSession(): ArkLabsSignerSession {
    return this.signerSessionFactory();
  }

  /**
   * Returns true while setArkLabsContext() has set a context that has not yet
   * been consumed by sign().  VtxoManager uses this to skip automatic renewal
   * attempts during the window between setArkLabsContext() and the intended
   * wallet.send() / ramps.offboard() signing call, preventing background
   * settle operations from stealing the context.
   */
  hasPendingContext(): boolean {
    return this._contextLockRelease !== null;
  }

  async signMessage(
    _message: Uint8Array,
    _type: 'schnorr' | 'ecdsa',
  ): Promise<Uint8Array> {
    throw new SigbashArkLabsSigningError(
      'SigbashArkLabsIdentity does not support signMessage; use sign(tx) via wallet operations',
    );
  }

  async sign(tx: T, _inputIndexes?: number[]): Promise<T> {
    // Serialize concurrent sign() calls so that a background wallet settle
    // cannot interfere with the sign_with_hash_auth pre-flight of a test sign.
    let releaseLock!: () => void;
    const prevLock = this.signingLock;
    this.signingLock = new Promise<void>((resolve) => { releaseLock = resolve; });

    // If setArkLabsContext() is holding the lock, release it so prevLock resolves.
    // This must happen BEFORE awaiting prevLock to avoid a deadlock: the context
    // lock IS prevLock, so we must release it before we can await it.
    if (this._contextLockRelease) {
      const contextRelease = this._contextLockRelease;
      this._contextLockRelease = null;
      contextRelease();
    }

    await prevLock;

    try {
      // Ark intent proof PSBTs have input[0] as a BIP-322 toSpend reference with
      // witnessUtxo.amount=0.  The ts-sdk's craftToSignTx() accidentally spreads
      // tapLeafScript onto input[0] from the first vtxo coin, causing the WASM to
      // produce a tapscript signature instead of the keypath signature that arkd
      // expects for the toSpend input.  Clear tapLeafScript from input[0] when its
      // amount is 0 so the WASM uses the keypath signing path.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const input0 = (tx as any).getInput?.(0);
      if (input0?.witnessUtxo?.amount === 0n && input0?.tapLeafScript?.length > 0) {
        // Pass tapLeafScript: undefined (key present, value undefined) so mergeKeyMap
        // removes it from the PSBT, forcing keypath signing for this input.
        // Use _ignoreSignStatus=true to bypass sign-status field restrictions.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (tx as any).updateInput(0, { tapLeafScript: undefined }, true);
      }

      // An Ark register-intent PSBT is identified by two Ark-specific conditions:
      //   1. input[0].witnessUtxo.amount === 0n  (BIP-322 toSpend fake)
      //   2. the raw PSBT bytes contain key 0xDE+"taptree"  (Ark VtxoTaprootTree field)
      // No generic spending PSBT carries the 0xDE taptree unknown field.
      // Intent proofs are allowed unconditionally by WASM and must NOT consume the
      // ArkLabsContext — preserving it for the subsequent arkTx that needs it.
      const psbtBytes = tx.toPSBT();
      const isIntentProof = input0?.witnessUtxo?.amount === 0n &&
        Buffer.from(psbtBytes).indexOf(ARK_TAPTREE_KEY) !== -1;

      const psbtBase64 = Buffer.from(psbtBytes).toString('base64');
      // Temporary investigation log — remove after confirming FORFEIT/CHECKPOINT call paths.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const inputCount = (tx as any).inputsLength ?? '?';
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const outputCount = (tx as any).outputsLength ?? '?';
      ++this._signCount;
      if (isIntentProof) ++this._intentProofSignCount;
      console.log(
        `[SigbashArkLabsIdentity.sign #${this._signCount}] ` +
        `inputs=${inputCount} outputs=${outputCount} ` +
        `intentProof=${isIntentProof} ` +
        `psbt=${psbtBase64.slice(0, 40)}...`,
      );

      // Consume context only for real spending PSBTs (non-intent-proofs).
      // Intent proofs pass undefined so WASM uses its unconditional allowance.
      const arkLabsIntentContext = isIntentProof ? undefined : (this.arkLabsCtx ?? undefined);
      if (!isIntentProof) {
        this.arkLabsCtx = null; // clear before the async call to prevent bleed
      }

      const result = await this.client.signPSBT({
        keyId: this.keyId,
        psbtBase64,
        kmcJSON: this.kmcJSON,
        network: this.network,
        arkLabsIntentContext,
      });

      if (!result.success) {
        throw new SigbashArkLabsSigningError(
          result.error ?? 'Sigbash refused to sign',
        );
      }

      return this.txFromPSBT(Buffer.from(result.signedPSBT!, 'base64'));
    } finally {
      releaseLock();
    }
  }
}
