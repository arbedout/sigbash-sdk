/**
 * Typed wallet errors. Static messages only: never key material, never
 * descriptor bytes, never derivation paths beyond what the caller passed in
 * and already knows.
 */

import { SigbashSDKError } from '../errors';

export class WalletDescriptorError extends SigbashSDKError {
  constructor(message: string) {
    super(message, 'WALLET_DESCRIPTOR_INVALID');
    this.name = 'WalletDescriptorError';
    Object.setPrototypeOf(this, WalletDescriptorError.prototype);
  }
}

export class WalletXpubError extends SigbashSDKError {
  constructor(message: string) {
    super(message, 'WALLET_XPUB_INVALID');
    this.name = 'WalletXpubError';
    Object.setPrototypeOf(this, WalletXpubError.prototype);
  }
}

export class WalletReqkeyTemplateError extends SigbashSDKError {
  constructor(message: string) {
    super(message, 'WALLET_REQKEY_TEMPLATE_INVALID');
    this.name = 'WalletReqkeyTemplateError';
    Object.setPrototypeOf(this, WalletReqkeyTemplateError.prototype);
  }
}

export class PsbtInputLimitError extends SigbashSDKError {
  constructor(inputCount: number, maxInputs: number) {
    super(
      `PSBT carries ${inputCount} inputs; a signing session is limited to ${maxInputs} inputs`,
      'PSBT_INPUT_LIMIT_EXCEEDED'
    );
    this.name = 'PsbtInputLimitError';
    Object.setPrototypeOf(this, PsbtInputLimitError.prototype);
  }
}

export class PsbtParseError extends SigbashSDKError {
  constructor(message: string) {
    super(message, 'PSBT_PARSE_FAILED');
    this.name = 'PsbtParseError';
    Object.setPrototypeOf(this, PsbtParseError.prototype);
  }
}
