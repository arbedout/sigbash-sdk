/**
 * Typed errors for the organization protocol key derivation. Static
 * messages only: never key material, never the rejected input value,
 * never any derived bytes.
 */

import { SigbashSDKError } from '../errors';

export type OrgProtocolKeyErrorCode =
  | 'founding-key-malformed'
  | 'org-client-id-malformed';

const ERROR_MESSAGES: Record<OrgProtocolKeyErrorCode, string> = {
  'founding-key-malformed':
    'the organization founding capability key must be exactly 32 bytes',
  'org-client-id-malformed': 'the organization client id is not a lowercase UUID',
};

export class OrgProtocolKeyError extends SigbashSDKError {
  override readonly code: OrgProtocolKeyErrorCode;

  constructor(code: OrgProtocolKeyErrorCode) {
    super(ERROR_MESSAGES[code], 'ORG_PROTOCOL_KEY_INVALID');
    this.name = 'OrgProtocolKeyError';
    this.code = code;
    Object.setPrototypeOf(this, OrgProtocolKeyError.prototype);
  }
}
