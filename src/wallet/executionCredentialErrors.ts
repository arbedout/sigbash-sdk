/**
 * Typed errors for the shared wallet execution credential. Static messages
 * only: never key material, never the rejected network or code value, never
 * any derived bytes.
 */

import { SigbashSDKError } from '../errors';

export type ExecutionCredentialErrorCode =
  | 'org-api-key-malformed'
  | 'user-key-malformed'
  | 'wallet-client-id-malformed'
  | 'epoch-key-malformed'
  | 'network-not-signet'
  | 'format-unsupported'
  | 'credential-malformed';

const ERROR_MESSAGES: Record<ExecutionCredentialErrorCode, string> = {
  'org-api-key-malformed': 'the organization protocol api key is not a 64-character hex string',
  'user-key-malformed': 'the wallet-domain user key is not a 64-character hex string',
  'wallet-client-id-malformed': 'the wallet client id is not a lowercase UUID',
  'epoch-key-malformed': 'the capability epoch key must be exactly 32 bytes',
  'network-not-signet': 'the shared wallet execution credential is valid on signet only',
  'format-unsupported': 'the execution credential format version is unsupported and fails closed',
  'credential-malformed': 'the execution credential serialization is malformed',
};

export class ExecutionCredentialError extends SigbashSDKError {
  override readonly code: ExecutionCredentialErrorCode;

  constructor(code: ExecutionCredentialErrorCode) {
    super(ERROR_MESSAGES[code], 'EXECUTION_CREDENTIAL_INVALID');
    this.name = 'ExecutionCredentialError';
    this.code = code;
    Object.setPrototypeOf(this, ExecutionCredentialError.prototype);
  }
}
