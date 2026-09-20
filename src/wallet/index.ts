/**
 * Institutional wallet helpers — the single SDK embedding surface for the
 * canonical institutional wallet representation. Consumers never grow their
 * own TapTree, descriptor text, fingerprint, or REQKEY template logic: every
 * byte the blind signer's proof system binds against flows through this
 * module, mirrored against the canonical WASM-lane builder via the golden
 * vectors in contracts/vectors/wallet-descriptor-v1.json.
 *
 * @packageDocumentation
 */

export * from './constants';
export * from './errors';
export {
  deriveWalletChildKey,
  originFingerprintToHex,
  parseWalletSignerOrigin,
  parseWalletXpubImport,
  splitOriginPrefixedXpub,
  validateWalletXpubImport,
} from './xpubImport';
export type { ParsedWalletXpub, WalletSignerOrigin } from './xpubImport';
export {
  buildInstitutionalWalletDescriptor,
  buildSigbashNativeMultisigWallet,
  buildSigbashPlusExternalWallet,
  buildSingleSigbashWallet,
  enumerateWalletSubsets,
  WALLET_SIGNER_KIND_ORDER,
} from './walletBuilder';
export type { InstitutionalWallet, WalletRecoveryBranches, WalletSigner, WalletSignerKind } from './walletBuilder';
export {
  canonicalWalletDescriptorText,
  canonicalWalletDescriptorTextWithChecksum,
  descriptorChecksum,
} from './canonicalText';
export type { CanonicalTextOptions, DescriptorBranch } from './canonicalText';
export {
  buildWalletTapTree,
  decayScript,
  deriveWalletReqkeyCandidate,
  liftX,
  pkScript,
  sortedMultiAScript,
  tapBranchHash,
} from './taptree';
export type { WalletTapLeaf, WalletTapLeafKind, WalletTapTree } from './taptree';
export {
  deriveWalletAddress,
  deriveWalletSpendMetadata,
  walletFingerprint,
  walletFingerprintHex,
  WALLET_FINGERPRINT_DOMAIN_TAG,
} from './walletIdentity';
export {
  decodeWalletReqkeyTemplate,
  encodeWalletCanonicalBytes,
  validateWalletReqkeyTemplate,
  walletReqkeyTemplatePayload,
} from './reqkeyTemplate';
export { parsePsbtInputCount } from './psbtInputCount';
