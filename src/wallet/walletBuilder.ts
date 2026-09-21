/**
 * Canonical institutional wallet construction.
 *
 * The canonical representation is an ordered signer-root list plus a
 * deterministic list of exact allowed signer subsets; every subset becomes
 * one all-keys-required sortedmulti_a tapscript leaf. The builder
 * normalizes and validates fail-closed: every ambiguity is an error, never
 * a silent normalization that another client might not reproduce. Canonical
 * orderings here are the single ordering authority for every later consumer
 * (canonical text, fingerprint, TapTree, REQKEY candidates).
 *
 * Signer-kind agnostic by construction: a Sigbash policy-bound BIP-328 root
 * and an external account xpub differ only in how their signatures are
 * produced later, never in tree shape.
 */

import {
  WALLET_BRANCH_CHANGE,
  WALLET_BRANCH_RECEIVE,
  WALLET_DECAY_BLOCKS_MAX,
  WALLET_DECAY_BLOCKS_MIN,
  WALLET_MAX_ALLOWED_SIGNER_SETS,
  WALLET_MAX_SIGNERS,
  WALLET_NETWORKS,
  type WalletNetwork,
} from './constants';
import { WalletDescriptorError } from './errors';
import { liftX } from './taptree';
import {
  deriveWalletChildKey,
  parseExtendedPublicKey,
  type WalletSignerOrigin,
} from './xpubImport';

export type WalletSignerKind = 'sigbash_policy_key' | 'external_xpub';

export const WALLET_SIGNER_KIND_ORDER: Record<WalletSignerKind, number> = {
  sigbash_policy_key: 1,
  external_xpub: 2,
};

export interface WalletSigner {
  kind: WalletSignerKind;
  /** Account derivation root (base58 extended public key, no origin prefix). */
  xpub: string;
  /** Required for sigbash_policy_key, forbidden for external_xpub. */
  policyKeyId?: string;
  /** Optional origin metadata, retained verbatim when supplied. */
  origin?: WalletSignerOrigin;
}

export interface WalletRecoveryBranches {
  /** Fixed customer-held 32-byte x-only key, embedded verbatim in the leaf. */
  recoveryKeyXOnly: Uint8Array;
  /** pk(RECOVERY_KEY) always-spendable branch. */
  alwaysSpendable: boolean;
  /** and_v(v:older(T),pk(RECOVERY_KEY)) decay branch. */
  decay: boolean;
  /** T in 1..65534; meaningful only when decay is true. */
  decayBlocks: number;
}

export interface InstitutionalWallet {
  network: WalletNetwork;
  /** Canonical signer order: kind, then xpub bytes, then policy key id. */
  signers: WalletSigner[];
  /** Ascending signer-index tuples, size 1..3, sorted lexicographically, deduplicated. */
  allowedSignerSets: number[][];
  /** At most one always-spendable and one decay branch, one shared key. */
  recovery?: WalletRecoveryBranches;
}

function assertValidXOnlyKey(key: Uint8Array, field: string): void {
  if (key.length !== 32) {
    throw new WalletDescriptorError(`${field} must be a 32-byte x-only key, got ${key.length} bytes`);
  }
  try {
    liftX(key);
  } catch {
    throw new WalletDescriptorError(`${field} is not a valid x-only public key`);
  }
}

function validateWalletNetwork(network: WalletNetwork): void {
  if (network === undefined || network === null || (network as string) === '') {
    throw new WalletDescriptorError('wallet network is required and must be explicit');
  }
  if (!WALLET_NETWORKS.includes(network)) {
    throw new WalletDescriptorError(`unsupported wallet network '${String(network)}'`);
  }
}

function validateWalletSigner(network: WalletNetwork, signer: WalletSigner): void {
  if (signer.kind === 'sigbash_policy_key') {
    if (!signer.policyKeyId) {
      throw new WalletDescriptorError('Sigbash signer is missing its policy key reference');
    }
  } else if (signer.kind === 'external_xpub') {
    if (signer.policyKeyId) {
      throw new WalletDescriptorError('external signer must not carry a policy key reference');
    }
  } else {
    throw new WalletDescriptorError('unknown signer kind');
  }
  if (!signer.xpub) {
    throw new WalletDescriptorError('signer xpub is required');
  }
  parseExtendedPublicKey(network, signer.xpub, 'signer xpub');
}

function validateSignerDerivations(wallet: InstitutionalWallet): void {
  for (let i = 0; i < wallet.signers.length; i++) {
    const { hd } = parseExtendedPublicKey(wallet.network, wallet.signers[i].xpub, 'signer xpub');
    for (const branch of [WALLET_BRANCH_RECEIVE, WALLET_BRANCH_CHANGE]) {
      try {
        deriveWalletChildKey(hd, branch, 0);
      } catch {
        throw new WalletDescriptorError(`signer ${i} cannot derive branch ${branch}`);
      }
    }
  }
}

function normalizeRecovery(recovery?: WalletRecoveryBranches): WalletRecoveryBranches | undefined {
  if (recovery === undefined) {
    return undefined;
  }
  if (!recovery.alwaysSpendable && !recovery.decay) {
    throw new WalletDescriptorError('recovery block carries neither an always-spendable nor a decay branch');
  }
  // A decay branch never exists without the always-spendable branch: the
  // shared record form has no always-spendable flag, so a recovery block's
  // presence IS the always-spendable fact and Decay alone is unrepresentable.
  if (recovery.decay && !recovery.alwaysSpendable) {
    throw new WalletDescriptorError(
      'decay-only recovery is not a valid wallet shape; the record form implies the always-spendable branch from block presence'
    );
  }
  if (recovery.decay && (recovery.decayBlocks < WALLET_DECAY_BLOCKS_MIN || recovery.decayBlocks > WALLET_DECAY_BLOCKS_MAX)) {
    throw new WalletDescriptorError(
      `decay block count ${recovery.decayBlocks} outside ${WALLET_DECAY_BLOCKS_MIN}..${WALLET_DECAY_BLOCKS_MAX}`
    );
  }
  assertValidXOnlyKey(recovery.recoveryKeyXOnly, 'recovery key');
  return {
    recoveryKeyXOnly: new Uint8Array(recovery.recoveryKeyXOnly),
    alwaysSpendable: recovery.alwaysSpendable,
    decay: recovery.decay,
    decayBlocks: recovery.decayBlocks,
  };
}

function indexTupleLess(a: number[], b: number[]): boolean {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) {
      return a[i] < b[i];
    }
  }
  return a.length < b.length;
}

function indexTupleEqual(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Normalizes, validates, and returns the canonical wallet descriptor.
 * Callers may pass signers and sets in any order; byte-identical canonical
 * output is guaranteed by the builder-applied ordering.
 */
export function buildInstitutionalWalletDescriptor(params: {
  network: WalletNetwork;
  signers: WalletSigner[];
  allowedSignerSets: number[][];
  recovery?: WalletRecoveryBranches;
}): InstitutionalWallet {
  const { network, signers: inputSigners, allowedSignerSets: inputSets, recovery: inputRecovery } = params;
  validateWalletNetwork(network);
  if (inputSigners.length === 0) {
    throw new WalletDescriptorError('wallet descriptor requires at least one signer');
  }
  if (inputSigners.length > WALLET_MAX_SIGNERS) {
    throw new WalletDescriptorError(`wallet descriptor supports at most ${WALLET_MAX_SIGNERS} signer roots, got ${inputSigners.length}`);
  }

  const canonical = [...inputSigners].sort((a, b) => {
    const kindDelta = WALLET_SIGNER_KIND_ORDER[a.kind] - WALLET_SIGNER_KIND_ORDER[b.kind];
    if (kindDelta !== 0) {
      return kindDelta;
    }
    if (a.xpub !== b.xpub) {
      return a.xpub < b.xpub ? -1 : 1;
    }
    return (a.policyKeyId ?? '') < (b.policyKeyId ?? '') ? -1 : (a.policyKeyId ?? '') > (b.policyKeyId ?? '') ? 1 : 0;
  });

  const seenXpub = new Set<string>();
  const seenPolicyKey = new Set<string>();
  for (const signer of canonical) {
    validateWalletSigner(network, signer);
    if (seenXpub.has(signer.xpub)) {
      throw new WalletDescriptorError('duplicate signer xpub');
    }
    seenXpub.add(signer.xpub);
    if (signer.kind === 'sigbash_policy_key') {
      if (seenPolicyKey.has(signer.policyKeyId!)) {
        throw new WalletDescriptorError('duplicate Sigbash policy key reference');
      }
      seenPolicyKey.add(signer.policyKeyId!);
    }
  }

  if (inputSets.length === 0) {
    throw new WalletDescriptorError('wallet descriptor requires at least one allowed signer set');
  }
  if (inputSets.length > WALLET_MAX_ALLOWED_SIGNER_SETS) {
    throw new WalletDescriptorError(
      `wallet descriptor supports at most ${WALLET_MAX_ALLOWED_SIGNER_SETS} allowed signer sets, got ${inputSets.length}`
    );
  }
  const sets: number[][] = inputSets.map((set, i) => {
    if (set.length < 1 || set.length > 3) {
      throw new WalletDescriptorError(`allowed signer set ${i} has ${set.length} keys; every leaf carries 1..3 keys`);
    }
    const normalized = [...set].sort((a, b) => a - b);
    for (let a = 1; a < normalized.length; a++) {
      if (normalized[a] === normalized[a - 1]) {
        throw new WalletDescriptorError(`allowed signer set ${i} repeats signer index ${normalized[a]}`);
      }
    }
    let hasSigbash = false;
    for (const idx of normalized) {
      if (idx >= canonical.length) {
        throw new WalletDescriptorError(`allowed signer set ${i} references signer index ${idx} outside the signer set`);
      }
      if (canonical[idx].kind === 'sigbash_policy_key') {
        hasSigbash = true;
      }
    }
    if (!hasSigbash) {
      throw new WalletDescriptorError(`allowed signer set ${i} contains no Sigbash policy-bound signer`);
    }
    return normalized;
  });
  sets.sort((a, b) => (indexTupleLess(a, b) ? -1 : indexTupleLess(b, a) ? 1 : 0));
  for (let i = 1; i < sets.length; i++) {
    if (indexTupleEqual(sets[i], sets[i - 1])) {
      throw new WalletDescriptorError(`duplicate allowed signer set at position ${i}`);
    }
  }

  const recovery = normalizeRecovery(inputRecovery);

  const wallet: InstitutionalWallet = {
    network,
    signers: canonical.map((s) => ({
      kind: s.kind,
      xpub: s.xpub,
      ...(s.policyKeyId !== undefined ? { policyKeyId: s.policyKeyId } : {}),
      ...(s.origin !== undefined
        ? {
            origin: {
              masterFingerprint: new Uint8Array(s.origin.masterFingerprint),
              path: [...s.origin.path],
            },
          }
        : {}),
    })),
    allowedSignerSets: sets,
    ...(recovery !== undefined ? { recovery } : {}),
  };

  // Every signer root must derive valid children for both canonical
  // branches (and carry network-matching version bytes) before the wallet
  // exists.
  validateSignerDerivations(wallet);
  return wallet;
}

/** Returns every exact k-member ascending index subset of 0..n-1, lexicographic. */
export function enumerateWalletSubsets(n: number, k: number): number[][] {
  const sets: number[][] = [];
  const current: number[] = [];
  const walk = (start: number): void => {
    if (current.length === k) {
      sets.push([...current]);
      return;
    }
    for (let i = start; i < n; i++) {
      current.push(i);
      walk(i + 1);
      current.pop();
    }
  };
  walk(0);
  return sets;
}

/** Single-Sigbash template: one policy-bound signer, one one-key leaf. */
export function buildSingleSigbashWallet(network: WalletNetwork, sigbash: WalletSigner): InstitutionalWallet {
  return buildInstitutionalWalletDescriptor({ network, signers: [sigbash], allowedSignerSets: [[0]] });
}

/** Sigbash-native M-of-N template: N<=5 policy-bound roots, M<=3, every exact subset. */
export function buildSigbashNativeMultisigWallet(
  network: WalletNetwork,
  sigbashSigners: WalletSigner[],
  threshold: number
): InstitutionalWallet {
  if (sigbashSigners.length > 5) {
    throw new WalletDescriptorError(`Sigbash-native template supports at most 5 signer roots, got ${sigbashSigners.length}`);
  }
  if (threshold < 1 || threshold > 3) {
    throw new WalletDescriptorError(`Sigbash-native threshold must be 1..3, got ${threshold}`);
  }
  if (threshold > sigbashSigners.length) {
    throw new WalletDescriptorError(`threshold ${threshold} exceeds the ${sigbashSigners.length} provided Sigbash signers`);
  }
  return buildInstitutionalWalletDescriptor({
    network,
    signers: sigbashSigners,
    allowedSignerSets: enumerateWalletSubsets(sigbashSigners.length, threshold),
  });
}

/**
 * Mixed template: one mandatory Sigbash policy-bound signer plus any
 * externalThreshold-of-N of the external roots (1 or 2; the combined leaf
 * stays within the three-key bound).
 */
export function buildSigbashPlusExternalWallet(
  network: WalletNetwork,
  sigbash: WalletSigner,
  externals: WalletSigner[],
  externalThreshold: number
): InstitutionalWallet {
  if (externals.length === 0 || externals.length > 5) {
    throw new WalletDescriptorError(`mixed template supports 1..5 external signer roots, got ${externals.length}`);
  }
  if (externalThreshold < 1 || externalThreshold > 2) {
    throw new WalletDescriptorError(`mixed template external threshold must be 1 or 2, got ${externalThreshold}`);
  }
  if (externalThreshold > externals.length) {
    throw new WalletDescriptorError(`external threshold ${externalThreshold} exceeds the ${externals.length} provided external signers`);
  }
  const externalSets = enumerateWalletSubsets(externals.length, externalThreshold);
  return buildInstitutionalWalletDescriptor({
    network,
    signers: [sigbash, ...externals],
    allowedSignerSets: externalSets.map((set) => [0, ...set.map((idx) => idx + 1)]),
  });
}

/**
 * Converts a versioned wallet record (the cross-component contract form)
 * into builder input. The contract record carries the sync-visible shape
 * (signer roots, allowed signer sets, recovery key, wallet mode) while the
 * canonical builder owns spend identity; construction here re-runs the full
 * fail-closed validation either way. Contract records cap the decay block
 * count one below the canonical format's 65535 because 0xffff is reserved
 * in that encoding; a record can never express a 65535-block decay branch.
 */
export function institutionalWalletFromContractRecord(record: {
  network: WalletNetwork;
  walletMode: 'sigbash_native' | 'mixed';
  signers: { kind: WalletSignerKind; xpub: string; policyKeyId?: string }[];
  allowedSignerSets: { signerIndexes: number[] }[];
  recovery?: { recoveryKeyXOnly: Uint8Array; decayBlocks: number | null };
}): InstitutionalWallet {
  const signers: WalletSigner[] = record.signers.map((signer) => ({
    kind: signer.kind,
    xpub: signer.xpub,
    ...(signer.policyKeyId !== undefined ? { policyKeyId: signer.policyKeyId } : {}),
  }));
  const sigbashCount = signers.filter((s) => s.kind === 'sigbash_policy_key').length;
  if (record.walletMode === 'sigbash_native' && sigbashCount !== signers.length) {
    throw new WalletDescriptorError('sigbash_native wallet record carries external signer roots');
  }
  return buildInstitutionalWalletDescriptor({
    network: record.network,
    signers,
    allowedSignerSets: record.allowedSignerSets.map((set) => [...set.signerIndexes]),
    ...(record.recovery !== undefined
      ? {
          recovery: {
            recoveryKeyXOnly: record.recovery.recoveryKeyXOnly,
            alwaysSpendable: true,
            decay: record.recovery.decayBlocks !== null,
            decayBlocks: record.recovery.decayBlocks ?? WALLET_DECAY_BLOCKS_MIN,
          },
        }
      : {}),
  });
}
