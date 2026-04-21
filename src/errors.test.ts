import {
  SigbashError,
  PolicyValidationError,
  AuthenticationError,
  WasmError,
  NetworkMismatchError,
  CryptoError,
  ServerError,
  TimeoutError,
  SigbashSDKError,
  KeyIndexExistsError,
  MissingOptionError,
  AdminError,
  TOTPRequiredError,
  TOTPInvalidError,
  TOTPSetupIncompleteError,
  NetworkError,
  parseServerError,
} from './errors';
import { ErrorCode } from './types';

// ---------------------------------------------------------------------------
// Shared instances used across multiple test groups
// ---------------------------------------------------------------------------

const sampleIssues = [{ path: 'policy', code: 'ERR', message: 'bad' }];

const instances: [string, Error][] = [
  ['SigbashError',             new SigbashError('sigbash error')],
  ['PolicyValidationError',    new PolicyValidationError('policy error', sampleIssues)],
  ['AuthenticationError',      new AuthenticationError('auth error')],
  ['WasmError',                new WasmError('wasm error')],
  ['NetworkMismatchError',     new NetworkMismatchError('mainnet', 'signet')],
  ['CryptoError',              new CryptoError('crypto error')],
  ['ServerError',              new ServerError('server error')],
  ['TimeoutError',             new TimeoutError('sign', 5000)],
  ['SigbashSDKError',          new SigbashSDKError('sdk error', 'SOME_CODE')],
  ['KeyIndexExistsError',      new KeyIndexExistsError(3, 4)],
  ['MissingOptionError',       new MissingOptionError('apiKey')],
  ['AdminError',               new AdminError()],
  ['TOTPRequiredError',        new TOTPRequiredError()],
  ['TOTPInvalidError',         new TOTPInvalidError()],
  ['TOTPSetupIncompleteError', new TOTPSetupIncompleteError()],
  ['NetworkError',             new NetworkError()],
];

// ---------------------------------------------------------------------------
// 1–16: instanceof checks (one it per class)
// ---------------------------------------------------------------------------

describe('instanceof checks', () => {
  it('SigbashError is instanceof SigbashError and Error', () => {
    const err = new SigbashError('msg');
    expect(err).toBeInstanceOf(SigbashError);
    expect(err).toBeInstanceOf(Error);
  });

  it('PolicyValidationError is instanceof PolicyValidationError, SigbashError, and Error', () => {
    const err = new PolicyValidationError('msg', sampleIssues);
    expect(err).toBeInstanceOf(PolicyValidationError);
    expect(err).toBeInstanceOf(SigbashError);
    expect(err).toBeInstanceOf(Error);
  });

  it('AuthenticationError is instanceof AuthenticationError, SigbashError, and Error', () => {
    const err = new AuthenticationError('msg');
    expect(err).toBeInstanceOf(AuthenticationError);
    expect(err).toBeInstanceOf(SigbashError);
    expect(err).toBeInstanceOf(Error);
  });

  it('WasmError is instanceof WasmError, SigbashError, and Error', () => {
    const err = new WasmError('msg');
    expect(err).toBeInstanceOf(WasmError);
    expect(err).toBeInstanceOf(SigbashError);
    expect(err).toBeInstanceOf(Error);
  });

  it('NetworkMismatchError is instanceof NetworkMismatchError, SigbashError, and Error', () => {
    const err = new NetworkMismatchError('mainnet', 'signet');
    expect(err).toBeInstanceOf(NetworkMismatchError);
    expect(err).toBeInstanceOf(SigbashError);
    expect(err).toBeInstanceOf(Error);
  });

  it('CryptoError is instanceof CryptoError, SigbashError, and Error', () => {
    const err = new CryptoError('msg');
    expect(err).toBeInstanceOf(CryptoError);
    expect(err).toBeInstanceOf(SigbashError);
    expect(err).toBeInstanceOf(Error);
  });

  it('ServerError is instanceof ServerError, SigbashError, and Error', () => {
    const err = new ServerError('msg');
    expect(err).toBeInstanceOf(ServerError);
    expect(err).toBeInstanceOf(SigbashError);
    expect(err).toBeInstanceOf(Error);
  });

  it('TimeoutError is instanceof TimeoutError, SigbashError, and Error', () => {
    const err = new TimeoutError('op', 1000);
    expect(err).toBeInstanceOf(TimeoutError);
    expect(err).toBeInstanceOf(SigbashError);
    expect(err).toBeInstanceOf(Error);
  });

  it('SigbashSDKError is instanceof SigbashSDKError and Error', () => {
    const err = new SigbashSDKError('msg', 'CODE');
    expect(err).toBeInstanceOf(SigbashSDKError);
    expect(err).toBeInstanceOf(Error);
  });

  it('KeyIndexExistsError is instanceof KeyIndexExistsError, SigbashSDKError, and Error', () => {
    const err = new KeyIndexExistsError(0);
    expect(err).toBeInstanceOf(KeyIndexExistsError);
    expect(err).toBeInstanceOf(SigbashSDKError);
    expect(err).toBeInstanceOf(Error);
  });

  it('MissingOptionError is instanceof MissingOptionError, SigbashSDKError, and Error', () => {
    const err = new MissingOptionError('apiKey');
    expect(err).toBeInstanceOf(MissingOptionError);
    expect(err).toBeInstanceOf(SigbashSDKError);
    expect(err).toBeInstanceOf(Error);
  });

  it('AdminError is instanceof AdminError, SigbashSDKError, and Error', () => {
    const err = new AdminError();
    expect(err).toBeInstanceOf(AdminError);
    expect(err).toBeInstanceOf(SigbashSDKError);
    expect(err).toBeInstanceOf(Error);
  });

  it('TOTPRequiredError is instanceof TOTPRequiredError, SigbashSDKError, and Error', () => {
    const err = new TOTPRequiredError();
    expect(err).toBeInstanceOf(TOTPRequiredError);
    expect(err).toBeInstanceOf(SigbashSDKError);
    expect(err).toBeInstanceOf(Error);
  });

  it('TOTPInvalidError is instanceof TOTPInvalidError, SigbashSDKError, and Error', () => {
    const err = new TOTPInvalidError();
    expect(err).toBeInstanceOf(TOTPInvalidError);
    expect(err).toBeInstanceOf(SigbashSDKError);
    expect(err).toBeInstanceOf(Error);
  });

  it('TOTPSetupIncompleteError is instanceof TOTPSetupIncompleteError, SigbashSDKError, and Error', () => {
    const err = new TOTPSetupIncompleteError();
    expect(err).toBeInstanceOf(TOTPSetupIncompleteError);
    expect(err).toBeInstanceOf(SigbashSDKError);
    expect(err).toBeInstanceOf(Error);
  });

  it('NetworkError is instanceof NetworkError, SigbashSDKError, and Error', () => {
    const err = new NetworkError();
    expect(err).toBeInstanceOf(NetworkError);
    expect(err).toBeInstanceOf(SigbashSDKError);
    expect(err).toBeInstanceOf(Error);
  });
});

// ---------------------------------------------------------------------------
// 17: .name property correctness
// ---------------------------------------------------------------------------

describe('.name property', () => {
  it('each error class has the correct .name set on the instance', () => {
    const expected: [string, Error][] = [
      ['SigbashError',             new SigbashError('msg')],
      ['PolicyValidationError',    new PolicyValidationError('msg', sampleIssues)],
      ['AuthenticationError',      new AuthenticationError('msg')],
      ['WasmError',                new WasmError('msg')],
      ['NetworkMismatchError',     new NetworkMismatchError('mainnet', 'signet')],
      ['CryptoError',              new CryptoError('msg')],
      ['ServerError',              new ServerError('msg')],
      ['TimeoutError',             new TimeoutError('op', 1000)],
      ['SigbashSDKError',          new SigbashSDKError('msg', 'CODE')],
      ['KeyIndexExistsError',      new KeyIndexExistsError(0)],
      ['MissingOptionError',       new MissingOptionError('opt')],
      ['AdminError',               new AdminError()],
      ['TOTPRequiredError',        new TOTPRequiredError()],
      ['TOTPInvalidError',         new TOTPInvalidError()],
      ['TOTPSetupIncompleteError', new TOTPSetupIncompleteError()],
      ['NetworkError',             new NetworkError()],
    ];

    for (const [expectedName, err] of expected) {
      expect(err.name).toBe(expectedName);
    }
  });
});

// ---------------------------------------------------------------------------
// 18: .message non-empty
// ---------------------------------------------------------------------------

describe('.message non-empty', () => {
  it('every error instance has a non-empty .message', () => {
    for (const [className, err] of instances) {
      expect(err.message.length).toBeGreaterThan(0);
      // Provide context on failure
      if (err.message.length === 0) {
        throw new Error(`${className} has an empty .message`);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 19: SigbashError default code
// ---------------------------------------------------------------------------

describe('SigbashError defaults', () => {
  it('default code is ErrorCode.UNKNOWN when no code argument is given', () => {
    const err = new SigbashError('msg');
    expect(err.code).toBe(ErrorCode.UNKNOWN);
  });
});

// ---------------------------------------------------------------------------
// 20: PolicyValidationError .issues
// ---------------------------------------------------------------------------

describe('PolicyValidationError', () => {
  it('.issues array is accessible and matches what was passed in', () => {
    const issues = [{ path: 'policy', code: 'ERR', message: 'bad' }];
    const err = new PolicyValidationError('msg', issues);
    expect(err.issues).toEqual(issues);
    expect(Array.isArray(err.issues)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 21: NetworkMismatchError message content
// ---------------------------------------------------------------------------

describe('NetworkMismatchError', () => {
  it('message includes both expected and actual network names', () => {
    const err = new NetworkMismatchError('mainnet', 'signet');
    expect(err.message).toContain('mainnet');
    expect(err.message).toContain('signet');
  });
});

// ---------------------------------------------------------------------------
// 22: CryptoError code based on isEncryption flag
// ---------------------------------------------------------------------------

describe('CryptoError', () => {
  it('isEncryption=true sets code to ENCRYPTION_FAILED', () => {
    const err = new CryptoError('enc', true);
    expect(err.code).toBe(ErrorCode.ENCRYPTION_FAILED);
  });

  it('isEncryption=false sets code to DECRYPTION_FAILED', () => {
    const err = new CryptoError('dec', false);
    expect(err.code).toBe(ErrorCode.DECRYPTION_FAILED);
  });
});

// ---------------------------------------------------------------------------
// 23: TimeoutError message content
// ---------------------------------------------------------------------------

describe('TimeoutError', () => {
  it('message includes the operation name and timeout value', () => {
    const err = new TimeoutError('sign', 5000);
    expect(err.message).toContain('sign');
    expect(err.message).toContain('5000');
  });
});

// ---------------------------------------------------------------------------
// 24: KeyIndexExistsError.nextAvailableIndex
// ---------------------------------------------------------------------------

describe('KeyIndexExistsError', () => {
  it('.nextAvailableIndex equals the value passed to the constructor', () => {
    const err = new KeyIndexExistsError(3, 4);
    expect(err.nextAvailableIndex).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// 25: MissingOptionError.optionName
// ---------------------------------------------------------------------------

describe('MissingOptionError', () => {
  it('.optionName equals the value passed to the constructor', () => {
    const err = new MissingOptionError('apiKey');
    expect(err.optionName).toBe('apiKey');
  });
});

// ---------------------------------------------------------------------------
// 26–29: parseServerError routing
// ---------------------------------------------------------------------------

describe('parseServerError', () => {
  it('routes INVALID_POLICY + issues to PolicyValidationError', () => {
    const result = parseServerError({
      code: 'INVALID_POLICY',
      issues: [{ path: 'policy', code: 'ERR', message: 'bad' }],
      message: 'bad policy',
    });
    expect(result).toBeInstanceOf(PolicyValidationError);
  });

  it('routes AUTH_FAILED to AuthenticationError', () => {
    const result = parseServerError({
      code: 'AUTH_FAILED',
      message: 'bad auth',
    });
    expect(result).toBeInstanceOf(AuthenticationError);
  });

  it('routes NETWORK_MISMATCH + expected + actual to NetworkMismatchError', () => {
    const result = parseServerError({
      code: 'NETWORK_MISMATCH',
      expected: 'mainnet',
      actual: 'signet',
      message: 'mismatch',
    });
    expect(result).toBeInstanceOf(NetworkMismatchError);
  });

  it('routes an unrecognised code to ServerError', () => {
    const result = parseServerError({
      code: 'OTHER',
      message: 'unknown',
    });
    expect(result).toBeInstanceOf(ServerError);
  });
});
