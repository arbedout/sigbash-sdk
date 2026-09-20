/**
 * Shared wallet execution credential suite: derivation determinism,
 * cross-implementation golden vectors, canonical serialization, fail-closed
 * Signet-only construction, and hygiene pins.
 *
 * The golden vectors are dual-purpose: the application backend test suite
 * re-derives the same values with an independent Python oracle (mirroring
 * the DESC-05 vector discipline), so a drift in either implementation or in
 * the registration-path format expectations fails on one side or the other.
 *
 * Source-scan pins enforce the module's hygiene contract: the credential
 * surface never imports the TOTP domain, never imports the legacy client
 * module, and never contains a logging call.
 */

import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  EXECUTION_CREDENTIAL_FORMAT_VERSION,
  EXECUTION_CREDENTIAL_HKDF_PREFIX,
  EXECUTION_CREDENTIAL_MAGIC,
  deriveWalletExecutionCredential,
  executionCredentialAuthHash,
  executionCredentialRegistrationMaterial,
  parseWalletExecutionCredential,
  serializeWalletExecutionCredential,
  walletExecutionCredentialsEqual,
} from './executionCredential';
import { ExecutionCredentialError } from './executionCredentialErrors';
import { getAuthHash } from '../credentials';

const ORG_API_KEY = '11'.repeat(32);
const WALLET_CLIENT_ID = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0';
/** Fixed founding (epoch 1) wallet capability key: 32 bytes of 0x42. */
const EPOCH1_KEY = new Uint8Array(32).fill(0x42);
const OTHER_WALLET_CLIENT_ID = 'a1b2c3d4-e5f6-4789-8a9b-0c1d2e3f4a5b';

const DERIVED = deriveWalletExecutionCredential(ORG_API_KEY, EPOCH1_KEY, WALLET_CLIENT_ID);

describe('execution credential derivation', () => {
  it('derives a 64-hex user key and secret with the signet posture pinned', () => {
    expect(DERIVED.formatVersion).toBe(EXECUTION_CREDENTIAL_FORMAT_VERSION);
    expect(DERIVED.network).toBe('signet');
    expect(DERIVED.userKey).toMatch(/^[0-9a-f]{64}$/);
    expect(DERIVED.userSecretKey).toMatch(/^[0-9a-f]{64}$/);
    expect(DERIVED.walletClientIdHex).toBe(WALLET_CLIENT_ID);
    expect(DERIVED.orgApiKey).toBe(ORG_API_KEY);
  });

  it('derives byte-identical material for an independent caller (convergence)', () => {
    const second = deriveWalletExecutionCredential(ORG_API_KEY, EPOCH1_KEY, WALLET_CLIENT_ID.toUpperCase());
    expect(walletExecutionCredentialsEqual(DERIVED, second)).toBe(true);
  });

  it('binds the principal to the wallet domain: another wallet derives different material', () => {
    const other = deriveWalletExecutionCredential(ORG_API_KEY, EPOCH1_KEY, OTHER_WALLET_CLIENT_ID);
    expect(walletExecutionCredentialsEqual(DERIVED, other)).toBe(false);
    expect(other.userKey).not.toBe(DERIVED.userKey);
    expect(other.userSecretKey).not.toBe(DERIVED.userSecretKey);
  });

  it('binds the secret to the epoch key: different seed derives different material', () => {
    const otherSeed = deriveWalletExecutionCredential(ORG_API_KEY, new Uint8Array(32).fill(0x43), WALLET_CLIENT_ID);
    expect(otherSeed.userSecretKey).not.toBe(DERIVED.userSecretKey);
  });

  it('fails closed on a malformed epoch key, org api key, or wallet client id', () => {
    expect(() => deriveWalletExecutionCredential(ORG_API_KEY, new Uint8Array(31), WALLET_CLIENT_ID))
      .toThrow(ExecutionCredentialError);
    expect(() => deriveWalletExecutionCredential('zz', EPOCH1_KEY, WALLET_CLIENT_ID))
      .toThrow(ExecutionCredentialError);
    expect(() => deriveWalletExecutionCredential(ORG_API_KEY, EPOCH1_KEY, 'not-a-uuid'))
      .toThrow(ExecutionCredentialError);
  });

  it('computes the auth hash synchronously and matches the shared auth module', async () => {
    const syncHash = executionCredentialAuthHash(ORG_API_KEY, DERIVED.userKey);
    const shared = await getAuthHash(ORG_API_KEY, DERIVED.userKey);
    expect(syncHash).toBe(shared.authHash);
    expect(syncHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces registration material with a 64-hex PoP public key and no secret', async () => {
    const material = await executionCredentialRegistrationMaterial(DERIVED);
    expect(material.authHashHex).toBe(executionCredentialAuthHash(ORG_API_KEY, DERIVED.userKey));
    expect(material.userKeyHex).toBe(DERIVED.userKey);
    expect(material.popPublicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(material)).not.toContain(DERIVED.userSecretKey);
  });
});

describe('execution credential golden vectors', () => {
  it('derives the pinned material for the fixed inputs (python-oracle mirror)', () => {
    // These goldens are re-derived by the application backend's independent
    // HKDF oracle; changing either side without the other must fail here.
    expect(DERIVED.userKey).toBe(
      '3ce6a02a87551551e90bba491f3305dc7fb2094e736962240fa7e9fb87ed3bf4',
    );
    expect(DERIVED.userSecretKey).toBe(
      '28af83adc59ea9322af496b3ffd474b8d0305ab32583a5bc3657bd02b67daad3',
    );
    expect(executionCredentialAuthHash(ORG_API_KEY, DERIVED.userKey)).toBe(
      'cc7313589b3c71f595a3592127f6dedef47a40a2fecc418682c18aa4a062682b',
    );
  });

  it('serializes to the pinned canonical bytes and round-trips', () => {
    const bytes = serializeWalletExecutionCredential(DERIVED);
    // 9 magic + 1 version + 3 x 32 + 16 uuid + 1 network code
    expect(bytes.length).toBe(9 + 1 + 32 + 32 + 32 + 16 + 1);
    expect(new TextDecoder().decode(bytes.slice(0, 9))).toBe(EXECUTION_CREDENTIAL_MAGIC);
    const parsed = parseWalletExecutionCredential(bytes);
    expect(walletExecutionCredentialsEqual(parsed, DERIVED)).toBe(true);
  });
});

describe('execution credential fail-closed parsing', () => {
  const good = serializeWalletExecutionCredential(DERIVED);

  it('rejects truncated and oversized inputs', () => {
    expect(() => parseWalletExecutionCredential(good.slice(0, good.length - 1))).toThrow(ExecutionCredentialError);
    expect(() => parseWalletExecutionCredential(new Uint8Array([...good, 0x00]))).toThrow(ExecutionCredentialError);
    expect(() => parseWalletExecutionCredential(new Uint8Array(0))).toThrow(ExecutionCredentialError);
  });

  it('rejects a wrong magic', () => {
    const bad = Uint8Array.from(good);
    bad[0] = 0x58; // 'X' -> 'XIGAEXEC1'
    expect(() => parseWalletExecutionCredential(bad)).toThrow(ExecutionCredentialError);
  });

  it('rejects an unknown format version', () => {
    const bad = Uint8Array.from(good);
    bad[9] = 0x02;
    expect(() => parseWalletExecutionCredential(bad)).toThrow(ExecutionCredentialError);
  });

  it('rejects a non-signet network code without echoing it', () => {
    const bad = Uint8Array.from(good);
    bad[bad.length - 1] = 0x00;
    try {
      parseWalletExecutionCredential(bad);
      throw new Error('parse must fail closed');
    } catch (err) {
      expect(err).toBeInstanceOf(ExecutionCredentialError);
      expect((err as ExecutionCredentialError).code).toBe('network-not-signet');
      expect((err as Error).message).not.toContain('0');
    }
  });

  it('rejects construction for a non-signet network without echoing it', () => {
    try {
      serializeWalletExecutionCredential({ ...DERIVED, network: 'mainnet' as never });
      throw new Error('serialization must fail closed');
    } catch (err) {
      expect(err).toBeInstanceOf(ExecutionCredentialError);
      expect((err as ExecutionCredentialError).code).toBe('network-not-signet');
    }
  });
});

describe('execution credential hygiene pins', () => {
  const MODULES = ['executionCredential.ts', 'executionCredentialErrors.ts'];

  function source(name: string): string {
    return readFileSync(join(resolve(__dirname), name), 'utf8');
  }

  it('never touches the TOTP domain or the legacy client module', () => {
    for (const name of MODULES) {
      const text = source(name);
      expect(text).not.toMatch(/from\s+'[^']*totp[^']*'/);
      expect(text).not.toMatch(/require\([^)]*totp/i);
      expect(text).not.toMatch(/SigbashClient/);
    }
  });

  it('never logs', () => {
    for (const name of MODULES) {
      expect(source(name)).not.toMatch(/console\.|logger\.|logging/);
    }
  });

  it('pins the HKDF label prefix registry', () => {
    expect(EXECUTION_CREDENTIAL_HKDF_PREFIX).toBe('sigbash.executioncredential.v1');
    const text = source('executionCredential.ts');
    expect(text).toContain('`${EXECUTION_CREDENTIAL_HKDF_PREFIX}/user-key`');
    expect(text).toContain('`${EXECUTION_CREDENTIAL_HKDF_PREFIX}/user-secret`');
  });
});
