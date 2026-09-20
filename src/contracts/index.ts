/**
 * Cross-component contracts — the single versioned source of truth for
 * every structure that crosses a lane boundary (SPA, SDK, browser
 * sync/crypto, Flask backend, signing protocol).
 *
 * One canonical definition per contract lives here. Security-critical
 * commitments are never serialized by ad hoc JSON. Every structure
 * carries an explicit version and rejects unknown or incompatible
 * versions on decode. Deterministic golden vectors live in
 * vectors/contracts-v1.json and are asserted byte-identically by the SDK
 * test suite and the application backend's mirror test.
 *
 * @packageDocumentation
 */

export {
  ContractVersionError,
  u8be,
  u16be,
  u32be,
  u64be,
  concatBytes,
  lengthDelimited,
  utf8,
  taggedHash,
  bytesToHex,
  hexToBytes,
  assertFixedLength,
  readContractHeader,
  contractHeader,
} from './encoding';
export type { Decoder } from './encoding';

export {
  NETWORK_ID_VERSION,
  NETWORK_CODES,
  encodeNetworkId,
  decodeNetworkId,
  parseNetworkId,
} from './network';
export type { NetworkId } from './network';

export {
  WALLET_DESCRIPTOR_CONTRACT_ID,
  WALLET_DESCRIPTOR_VERSION,
  SUPPORTED_WALLET_DESCRIPTOR_VERSIONS,
  WALLET_SIGNER_KIND_CODES,
  WALLET_MODE_CODES,
  MAX_SIGNERS_PER_LEAF,
  encodeWalletDescriptorV1,
  decodeWalletDescriptorV1,
  walletDescriptorToHex,
  walletDescriptorFromHex,
} from './walletDescriptor';
export type { WalletDescriptorV1, WalletSignerKind, WalletSignerRootV1, WalletMode, AllowedSignerSetV1, RecoveryBranchV1 } from './walletDescriptor';

export {
  WALLET_ID_VERSION,
  WALLET_ID_TAG,
  WALLET_ID_LENGTH,
  computeWalletId,
  walletIdToHex,
  walletIdFromHex,
} from './walletId';
export type { WalletId } from './walletId';

export {
  APPROVAL_COMMITMENT_CONTRACT_ID,
  APPROVAL_COMMITMENT_VERSION,
  SUPPORTED_APPROVAL_COMMITMENT_VERSIONS,
  APPROVAL_COMMITMENT_TAG,
  APPROVAL_COMMITMENT_LENGTH,
  ApprovalCommitmentDecodeError,
  encodeApprovalCommitmentV1,
  decodeApprovalCommitmentV1,
  computeApprovalCommitment,
  approvalCommitmentToHex,
  hexField,
} from './approvalCommitment';
export type {
  ApprovalCommitmentFieldsV1,
  ApprovalCommitmentInputV1,
  ApprovalCommitmentOutputV1,
} from './approvalCommitment';

export {
  SYNC_ENVELOPE_CONTRACT_ID,
  EVENT_HEADER_CONTRACT_ID,
  ENCRYPTED_SYNC_ENVELOPE_VERSION,
  ENCRYPTED_EVENT_HEADER_VERSION,
  SUPPORTED_SYNC_ENVELOPE_VERSIONS,
  SUPPORTED_EVENT_HEADER_VERSIONS,
  CLIENT_EVENT_ID_LENGTH,
  CLIENT_ORG_ID_LENGTH,
  CLIENT_USER_ID_LENGTH,
  encodeEncryptedEventHeaderV1,
  decodeEncryptedEventHeaderV1,
} from './syncEnvelope';
export type { EncryptedEventHeaderV1 } from './syncEnvelope';

export {
  CAPABILITY_EPOCH_VERSION,
  CAPABILITY_GROUP_ORG_COMMON,
  CAPABILITY_GROUP_POLICY_GOVERNANCE,
  CAPABILITY_GROUP_AUDIT,
  CAPABILITY_GROUP_SECURITY_RECOVERY,
  CAPABILITY_GROUP_WALLET_PREFIX,
  walletCapabilityGroupId,
  parseCapabilityGroupId,
  encodeCapabilityEpoch,
} from './capability';

export {
  ROLE_PRESET_VERSION,
  CAPABILITY_ACTION_VERSION,
  ROLE_PRESET_ORG_OWNER,
  ROLE_PRESET_SECURITY_ADMIN,
  ROLE_PRESET_MANAGED_ORG_ADMIN,
  ROLE_PRESET_WALLET_ADMIN,
  ROLE_PRESET_POLICY_EDITOR,
  ROLE_PRESET_POLICY_APPROVER,
  ROLE_PRESET_TREASURY_OPERATOR,
  ROLE_PRESET_TX_APPROVER,
  ROLE_PRESET_SIGNER,
  ROLE_PRESET_AUDITOR,
  ROLE_PRESET_SERVICE_USER,
  ROLE_PRESETS,
  parseRolePreset,
  CAPABILITY_ORG_MEMBER_INVITE,
  CAPABILITY_ORG_MEMBER_REMOVE,
  CAPABILITY_ORG_ROLE_ASSIGN,
  CAPABILITY_ORG_SETTINGS_WRITE,
  CAPABILITY_ORG_SECURITY_SETTINGS_WRITE,
  CAPABILITY_ORG_RECOVERY_ASSIST,
  CAPABILITY_ORG_SYNC_ROTATE,
  CAPABILITY_ORG_MANAGED_PROVISION,
  CAPABILITY_WALLET_CREATE,
  CAPABILITY_WALLET_SIGNER_ADD,
  CAPABILITY_WALLET_ARCHIVE,
  CAPABILITY_WALLET_MIGRATE,
  CAPABILITY_POLICY_DRAFT,
  CAPABILITY_POLICY_APPROVE,
  CAPABILITY_TX_PROPOSE,
  CAPABILITY_TX_APPROVE,
  CAPABILITY_AUDIT_READ,
  CAPABILITY_TX_SIGN,
  CAPABILITY_ACTIONS,
  CAPABILITY_ACTION_SCOPES,
  HUMAN_APPROVAL_ACTIONS,
  PRESET_CAPABILITIES,
  PRESET_ORG_GROUPS,
  capabilityGroupsForPreset,
  parsePresetAssignment,
  parseOrgGovernanceSettings,
  DEFAULT_ORG_GOVERNANCE_SETTINGS,
} from './rolePresets';
export type {
  RolePreset,
  CapabilityActionId,
  CapabilityActionScope,
  PresetScope,
  PresetAssignment,
  OrgGovernanceSettings,
} from './rolePresets';

export {
  PROPOSAL_ID_VERSION,
  SIGNING_ATTEMPT_ID_VERSION,
  TRANSACTION_PROPOSAL_STATE_VERSION,
  SIGNING_ATTEMPT_STATE_VERSION,
  TRANSACTION_PROPOSAL_STATE_CODES,
  SIGNING_ATTEMPT_STATE_CODES,
  parseProposalId,
  parseSigningAttemptId,
  encodeTransactionProposalState,
  decodeTransactionProposalState,
  encodeSigningAttemptState,
  decodeSigningAttemptState,
  isProposalTerminal,
} from './proposal';
export type { TransactionProposalState, SigningAttemptState } from './proposal';

export {
  POLICY_VERSION_ID_VERSION,
  POLICY_ENFORCEMENT_CLASS_VERSION,
  POLICY_VERSION_STATE_VERSION,
  POLICY_ENFORCEMENT_CLASS_CODES,
  POLICY_VERSION_STATE_CODES,
  parsePolicyVersionId,
  encodePolicyEnforcementClass,
  decodePolicyEnforcementClass,
  encodePolicyVersionState,
  decodePolicyVersionState,
} from './policy';
export type { PolicyEnforcementClass, PolicyVersionState } from './policy';

export {
  CANONICAL_POLICY_AST_VERSION,
  canonicalJson,
  canonicalizePolicyRoot,
  parseCanonicalPolicyAst,
  policyNodeIdentityPaths,
} from './policyAst';
export type { CanonicalPolicyAstV1 } from './policyAst';
export type { ConditionNode, PolicyNode } from '../types';

export {
  CANONICAL_POLICY_CONTRACT_ID,
  CANONICAL_POLICY_VERSION,
  SUPPORTED_CANONICAL_POLICY_VERSIONS,
  POLICY_AST_DIGEST_TAG,
  POLICY_AST_DIGEST_LENGTH,
  encodeCanonicalPolicyAstV1,
  decodeCanonicalPolicyAstV1,
  canonicalPolicyAstToHex,
  canonicalPolicyAstFromHex,
  computePolicyAstDigest,
  policyAstDigestToHex,
  policyAstDigestHex,
} from './policyEncoding';

export {
  POLICY_TEMPLATE_CATALOGUE_VERSION,
  SOUNDNESS_CENSUS_VERDICTS,
  CENSUS_GRADED_CONDITION_COUNT,
  DISABLED_CONDITION_TYPES,
  POLICY_TEMPLATES,
  assertCatalogueInvariant,
  getPolicyTemplate,
  buildPolicyTemplateAst,
  buildGovernanceTemplateFact,
  createPolicyTemplateSelection,
  validatePolicySelectionAst,
  validatePolicyTemplateSelection,
} from './policyTemplates';
export type {
  SoundnessCensusVerdict,
  CensusVerdictRecord,
  PolicyTemplateDescriptorV1,
  HardPolicyTemplateDescriptorV1,
  GovernancePolicyTemplateDescriptorV1,
  PolicyTemplateParamSpecV1,
  GovernanceWorkflowFactV1,
  PolicyTemplateAstOutputV1,
  PolicyTemplateSelectionV1,
  PolicyConditionGateOptions,
} from './policyTemplates';

export {
  SYSTEM_POLICY_VERSION,
  SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE,
  SYSTEM_REQKEY_DERIVATION_RANGE,
  SYSTEM_POLICY_TAG,
  systemWalletOwnershipFragment,
  systemPolicyAst,
  composeEffectivePolicy,
  computeSystemPolicyDigest,
  systemPolicyDigestHex,
  computeEffectivePolicyDigest,
  effectivePolicyDigestHex,
  systemClauseIdentityDigestHex,
} from './systemPolicy';

export {
  RECOVERY_ENVELOPE_CONTRACT_ID,
  RECOVERY_ENVELOPE_VERSION,
  SUPPORTED_RECOVERY_ENVELOPE_VERSIONS,
  RECOVERY_QR_FORMAT_VERSION,
  encodeRecoveryEnvelopeVersion,
  decodeRecoveryEnvelopeVersion,
} from './recovery';

export {
  SIGNING_ERROR_CODESET_VERSION,
  SIGNING_API_ERROR_CODES,
  SIGNING_ERROR_CLASSES,
  signingFailureClass,
  isSigningSessionTerminal,
} from './errors';
export type { SigningApiErrorCode, SigningFailureClass } from './errors';
