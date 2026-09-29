import {
  authorizationKeyRoleOf,
  KEY_CAPABILITIES_DEFAULT,
  KEY_ORIGIN_DEFAULT,
  KEY_SCHEME_DEFAULT,
  keyModelMetadataOf,
  normalizeKeyModelMetadata,
  stampKeyModelMetadata,
  KeyModelMetadata,
} from './keyModel';

describe('key-model container metadata', () => {
  it('defaults every absent field on a legacy container', () => {
    const kmc: Record<string, unknown> = { key_index: 3, participants: [] };
    const out = normalizeKeyModelMetadata(kmc) as Record<string, unknown>;
    expect(out.origin).toBe(KEY_ORIGIN_DEFAULT);
    expect(out.scheme).toBe(KEY_SCHEME_DEFAULT);
    expect(out.capabilities).toEqual(KEY_CAPABILITIES_DEFAULT);
    expect(out.key_index).toBe(3);
  });

  it('keeps present values and rejects unknown ones as container corruption', () => {
    const present = normalizeKeyModelMetadata({ origin: 'user_provided', scheme: 'secp256k1_schnorr', capabilities: ['transaction_authorize'] }) as Record<string, unknown>;
    expect(present.origin).toBe('user_provided');
    expect(present.capabilities).toEqual(['transaction_authorize']);

    expect(() => normalizeKeyModelMetadata({ origin: 'hardware' })).toThrow(/origin/);
    expect(() => normalizeKeyModelMetadata({ scheme: 'ed25519' })).toThrow(/scheme/);
    expect(() => normalizeKeyModelMetadata({ capabilities: ['mint_tokens'] })).toThrow(/capabilities/);
    expect(() => normalizeKeyModelMetadata({ capabilities: ['bitcoin_sign', 'bitcoin_sign'] }))
      .toThrow(/duplicate/);
  });

  it('stamps metadata for rewrap with present values winning', () => {
    const byo = { origin: 'user_provided' };
    const stamped = stampKeyModelMetadata(byo) as Record<string, unknown>;
    expect(stamped).toBe(byo);
    expect(stamped.origin).toBe('user_provided');
    expect(stamped.scheme).toBe(KEY_SCHEME_DEFAULT);
    expect(stamped.capabilities).toEqual(KEY_CAPABILITIES_DEFAULT);
  });

  it('exposes a read-only copy view without mutating the container', () => {
    const kmc = { origin: 'user_provided', capabilities: ['transaction_authorize'] };
    const view: KeyModelMetadata = keyModelMetadataOf(kmc);
    expect(view.origin).toBe('user_provided');
    expect(view.capabilities).toEqual(['transaction_authorize']);
    expect((kmc as Record<string, unknown>).scheme).toBeUndefined();
  });
});

describe('authorizationKeyRoleOf — listing discriminator', () => {
  it('displays legacy containers as signing keys', () => {
    // A legacy container has no declared fields; the normalized view
    // defaults origin to 'sigbash' and capabilities to the signing set.
    const legacy = keyModelMetadataOf({});
    expect(authorizationKeyRoleOf(legacy)).toBe('signing');
  });

  it('follows the capabilities list, not origin alone', () => {
    expect(authorizationKeyRoleOf({ origin: 'user_provided', scheme: KEY_SCHEME_DEFAULT, capabilities: [] }))
      .toBe('authorization_only');
    expect(authorizationKeyRoleOf({ origin: 'user_provided', scheme: KEY_SCHEME_DEFAULT, capabilities: ['bitcoin_sign'] }))
      .toBe('signing');
    expect(authorizationKeyRoleOf({ origin: 'sigbash', scheme: KEY_SCHEME_DEFAULT, capabilities: ['transaction_authorize'] }))
      .toBe('authorization_only');
    expect(authorizationKeyRoleOf({ origin: 'sigbash', scheme: KEY_SCHEME_DEFAULT, capabilities: ['bitcoin_sign', 'transaction_authorize'] }))
      .toBe('signing_and_authorization');
    expect(authorizationKeyRoleOf({ origin: 'user_provided', scheme: KEY_SCHEME_DEFAULT, capabilities: ['bitcoin_sign', 'transaction_authorize'] }))
      .toBe('signing_and_authorization');
  });
});
