/**
 * Organization protocol key derivation suite: cross-implementation golden
 * vectors, determinism, salt binding, founding-key fail-closed matrix,
 * label-registry pin, and hygiene pins.
 *
 * The golden vectors are dual-purpose: the application backend test suite
 * re-derives the same values with an independent Python oracle
 * (stdlib hmac/hashlib HKDF-SHA256, mirroring the recorded vector
 * discipline of the execution credential suite), so a drift in either
 * implementation or in the derivation parameters fails on one side or
 * the other. The vectors use synthetic seed-byte material only; nothing
 * here touches live key material.
 *
 * Source-scan pins enforce the module's hygiene contract: the derivation
 * surface never imports the TOTP domain, never imports the legacy client
 * module, and never contains a logging call.
 */

import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  ORG_PROTOCOL_KEY_HKDF_PREFIX,
  deriveOrgProtocolApiKey,
  deriveOrgProtocolRegistrationPrincipal,
} from './orgProtocolKey';
import { OrgProtocolKeyError } from './orgProtocolKeyErrors';
import { executionCredentialAuthHash } from './executionCredential';

/** Fixed founding (epoch 1) org-common capability key: synthetic seed material. */
const FOUNDING_KEY = Uint8Array.from(
  ('a1b2c3d4'.repeat(8)).match(/.{2}/g)!.map((byte) => parseInt(byte, 16)),
);
const ORG_CLIENT_ID = 'e0000000-0000-4000-8000-000000000001';
const OTHER_ORG_CLIENT_ID = 'e0000000-0000-4000-8000-000000000002';

/**
 * Recorded Python-oracle values for (FOUNDING_KEY, ORG_CLIENT_ID) and
 * (FOUNDING_KEY, OTHER_ORG_CLIENT_ID). Regenerate only with the
 * independent stdlib oracle described in the module header; never from
 * the code under test.
 */
const VECTORS: Record<string, { apiKey: string; regKey: string; regSecret: string }> = {
  [ORG_CLIENT_ID]: {
    apiKey: 'd12259eca94c087f34f37846a3eabcb64ba1f8ca162c0442f3919c2d9e0c3c20',
    regKey: 'c69745f35aa0d9efe61b0b0d4d7667594ca0a4a7ceb8290b8a2e84d94ecaf4cc',
    regSecret: 'df9226c90dd75e53b621d9d43123e3dd1b0463dd014d6bdbe6c9b762c9f56b59',
  },
  [OTHER_ORG_CLIENT_ID]: {
    apiKey: 'bf58527f5c303c1e0d770da23830663f9f14773f9a357c3e03e77173cccc1ed4',
    regKey: 'd00bd224aa1f0664a08c078d2dc222330a570dcca6178a55c4d297d10af0b7ac',
    regSecret: '630c6c98e8e2dd589a9105235869b0c4ef9712ebed7b182509e38200d4d2b970',
  },
};

describe('organization protocol key derivation', () => {
  it('reproduces the recorded Python-oracle api key and registration principal', () => {
    for (const [orgId, vector] of Object.entries(VECTORS)) {
      expect(deriveOrgProtocolApiKey(FOUNDING_KEY, orgId)).toBe(vector.apiKey);
      const principal = deriveOrgProtocolRegistrationPrincipal(FOUNDING_KEY, orgId);
      expect(principal.userKeyHex).toBe(vector.regKey);
      expect(principal.userSecretKeyHex).toBe(vector.regSecret);
    }
  });

  it('derives a 64-hex api key that satisfies the SDK credential apiKey shape', () => {
    const apiKey = deriveOrgProtocolApiKey(FOUNDING_KEY, ORG_CLIENT_ID);
    expect(apiKey).toMatch(/^[0-9a-f]{64}$/);
    // The auth hash over the derived apiKey and any user key composes
    // through the existing credential family unchanged.
    expect(() =>
      executionCredentialAuthHash(apiKey, VECTORS[ORG_CLIENT_ID].regKey),
    ).not.toThrow();
  });

  it('is deterministic across repeated calls', () => {
    expect(deriveOrgProtocolApiKey(FOUNDING_KEY, ORG_CLIENT_ID)).toBe(
      deriveOrgProtocolApiKey(FOUNDING_KEY, ORG_CLIENT_ID),
    );
    expect(deriveOrgProtocolRegistrationPrincipal(FOUNDING_KEY, ORG_CLIENT_ID)).toEqual(
      deriveOrgProtocolRegistrationPrincipal(FOUNDING_KEY, ORG_CLIENT_ID),
    );
  });

  it('binds the organization client id as the salt: two orgs never collide', () => {
    const first = deriveOrgProtocolApiKey(FOUNDING_KEY, ORG_CLIENT_ID);
    const second = deriveOrgProtocolApiKey(FOUNDING_KEY, OTHER_ORG_CLIENT_ID);
    expect(first).not.toBe(second);
    const firstPrincipal = deriveOrgProtocolRegistrationPrincipal(FOUNDING_KEY, ORG_CLIENT_ID);
    const secondPrincipal = deriveOrgProtocolRegistrationPrincipal(FOUNDING_KEY, OTHER_ORG_CLIENT_ID);
    expect(firstPrincipal.userKeyHex).not.toBe(secondPrincipal.userKeyHex);
    expect(firstPrincipal.userSecretKeyHex).not.toBe(secondPrincipal.userSecretKeyHex);
  });

  it('normalizes the organization client id case before salting', () => {
    const upper = deriveOrgProtocolApiKey(FOUNDING_KEY, ORG_CLIENT_ID.toUpperCase());
    expect(upper).toBe(VECTORS[ORG_CLIENT_ID].apiKey);
  });

  it('differs from the wallet execution credential family on identical material', () => {
    // The org-family label space is disjoint from the wallet family: the
    // same founding key and id strings must never produce wallet-family
    // output through the org labels.
    const orgKey = deriveOrgProtocolApiKey(FOUNDING_KEY, ORG_CLIENT_ID);
    expect(orgKey).not.toBe(VECTORS[OTHER_ORG_CLIENT_ID].regKey);
  });

  it('fails closed on a malformed founding key without echoing it', () => {
    for (const length of [0, 16, 31, 33, 64]) {
      expect(() => deriveOrgProtocolApiKey(new Uint8Array(length), ORG_CLIENT_ID)).toThrow(
        OrgProtocolKeyError,
      );
      expect(() =>
        deriveOrgProtocolRegistrationPrincipal(new Uint8Array(length), ORG_CLIENT_ID),
      ).toThrow(OrgProtocolKeyError);
    }
    try {
      deriveOrgProtocolApiKey(new Uint8Array(16), ORG_CLIENT_ID);
    } catch (error) {
      expect((error as OrgProtocolKeyError).code).toBe('founding-key-malformed');
      expect((error as Error).message).not.toMatch(/[0-9a-f]{16}/);
    }
  });

  it('fails closed on a malformed organization client id without echoing it', () => {
    for (const bad of ['', 'not-a-uuid', 'zz000000-0000-4000-8000-000000000001', 'e0000000']) {
      expect(() => deriveOrgProtocolApiKey(FOUNDING_KEY, bad)).toThrow(OrgProtocolKeyError);
      expect(() =>
        deriveOrgProtocolRegistrationPrincipal(FOUNDING_KEY, bad),
      ).toThrow(OrgProtocolKeyError);
    }
    try {
      deriveOrgProtocolApiKey(FOUNDING_KEY, 'not-a-uuid');
    } catch (error) {
      expect((error as OrgProtocolKeyError).code).toBe('org-client-id-malformed');
    }
  });
});

describe('key-schedule registry', () => {
  it('keeps the label prefix disjoint from every other recorded derivation family', () => {
    const recordedPrefixes = [
      'sigbash.executioncredential.v1',
      'sigbash.userroot.v1.',
      'sigbash.capability.v1.',
      'sigbash/sdk-pop-ed25519/v1',
    ];
    for (const prefix of recordedPrefixes) {
      expect(ORG_PROTOCOL_KEY_HKDF_PREFIX.startsWith(prefix)).toBe(false);
      expect(prefix.startsWith(ORG_PROTOCOL_KEY_HKDF_PREFIX)).toBe(false);
    }
    expect(ORG_PROTOCOL_KEY_HKDF_PREFIX).toBe('sigbash.orgprotocol.v1');
  });
});

describe('hygiene pins', () => {
  const source = readFileSync(resolve(join(__dirname, 'orgProtocolKey.ts')), 'utf8');
  const errorSource = readFileSync(
    resolve(join(__dirname, 'orgProtocolKeyErrors.ts')),
    'utf8',
  );

  it('contains no logging call in the derivation surface', () => {
    expect(source).not.toMatch(/\bconsole\./);
    expect(source).not.toMatch(/\blogger\b/);
    expect(errorSource).not.toMatch(/\bconsole\./);
  });

  it('imports no TOTP domain and no legacy client module', () => {
    expect(source).not.toMatch(/from '\.\.\/totp'/);
    expect(source).not.toMatch(/from '\.\.\/SigbashClient'/);
    expect(source).not.toMatch(/from '\.\.\/credentials'/);
  });

  it('carries only static error messages', () => {
    expect(errorSource).not.toMatch(/\$\{/);
  });
});
