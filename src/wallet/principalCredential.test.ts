/**
 * Principal credential suite: generation freshness, auth-hash identity,
 * slot-key derivation determinism and org binding, canonical
 * serialization, fail-closed parsing, and hygiene pins.
 *
 * Source-scan pins enforce the module's hygiene contract: the slot-key
 * label space is disjoint from every other key-schedule family in the
 * codebase, and the module never imports the shared-execution-credential
 * domain — a principal replaces, never extends, that credential class.
 */

import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  PRINCIPAL_CREDENTIAL_FORMAT_VERSION,
  PRINCIPAL_CREDENTIAL_HKDF_PREFIX,
  PRINCIPAL_CREDENTIAL_MAGIC,
  derivePrincipalSlotKey,
  generatePrincipalCredential,
  parsePrincipalCredential,
  principalAuthHash,
  principalCredentialsEqual,
  principalPopPublicKeyHex,
  principalSlotCredentialId,
  serializePrincipalCredential,
  PrincipalCredentialError,
} from './principalCredential';
import { derivePopKey } from '../pop';
import { doubleSha256 } from '../auth';

const ORG_API_KEY = '11'.repeat(32);
const OTHER_ORG_API_KEY = '22'.repeat(32);

const GENERATED = generatePrincipalCredential(ORG_API_KEY);

describe('principal credential generation', () => {
  it('mints a versioned record with 64-hex identifiers', () => {
    expect(GENERATED.formatVersion).toBe(PRINCIPAL_CREDENTIAL_FORMAT_VERSION);
    expect(GENERATED.orgApiKey).toBe(ORG_API_KEY);
    expect(GENERATED.userKey).toMatch(/^[0-9a-f]{64}$/);
    expect(GENERATED.userSecretKey).toMatch(/^[0-9a-f]{64}$/);
    expect(GENERATED.userKey).not.toBe(GENERATED.userSecretKey);
  });

  it('never reuses material across generations', () => {
    const second = generatePrincipalCredential(ORG_API_KEY);
    expect(second.userKey).not.toBe(GENERATED.userKey);
    expect(second.userSecretKey).not.toBe(GENERATED.userSecretKey);
  });

  it('rejects a malformed org api key before anything is minted', () => {
    expect(() => generatePrincipalCredential('nothex')).toThrow(PrincipalCredentialError);
    expect(() => generatePrincipalCredential('a'.repeat(63))).toThrow(PrincipalCredentialError);
  });
});

describe('principal auth hash', () => {
  it('is the credential identity shape the server resolves: DSHA256(orgApiKey || userKey)', async () => {
    const hash = await principalAuthHash(ORG_API_KEY, GENERATED.userKey);
    expect(hash).toBe(await doubleSha256(ORG_API_KEY, GENERATED.userKey));
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('binds the organization: another org yields another hash', async () => {
    const hash = await principalAuthHash(ORG_API_KEY, GENERATED.userKey);
    const other = await principalAuthHash(OTHER_ORG_API_KEY, GENERATED.userKey);
    expect(other).not.toBe(hash);
  });

  it('rejects malformed inputs fail-closed', async () => {
    expect(() => principalAuthHash('zz', GENERATED.userKey)).toThrow(PrincipalCredentialError);
  });
});

describe('principal slot key derivation', () => {
  const SLOT = derivePrincipalSlotKey(ORG_API_KEY, GENERATED.userSecretKey);

  it('derives a compressed secp256k1 keypair deterministically', () => {
    expect(SLOT.publicKeyHex).toMatch(/^0[23][0-9a-f]{64}$/);
    expect(SLOT.privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
    const again = derivePrincipalSlotKey(ORG_API_KEY, GENERATED.userSecretKey);
    expect(again.privateKeyHex).toBe(SLOT.privateKeyHex);
    expect(again.publicKeyHex).toBe(SLOT.publicKeyHex);
  });

  it('binds the org: the same secret in another org derives another slot key', () => {
    const other = derivePrincipalSlotKey(OTHER_ORG_API_KEY, GENERATED.userSecretKey);
    expect(other.privateKeyHex).not.toBe(SLOT.privateKeyHex);
    expect(other.publicKeyHex).not.toBe(SLOT.publicKeyHex);
  });

  it('derives a distinct key per credential secret', () => {
    const other = derivePrincipalSlotKey(ORG_API_KEY, generatePrincipalCredential(ORG_API_KEY).userSecretKey);
    expect(other.privateKeyHex).not.toBe(SLOT.privateKeyHex);
  });

  it('rejects malformed inputs fail-closed', () => {
    expect(() => derivePrincipalSlotKey(ORG_API_KEY, 'short')).toThrow(PrincipalCredentialError);
  });
});

describe('canonical serialization', () => {
  it('round-trips byte-identically through parse', () => {
    const bytes = serializePrincipalCredential(GENERATED);
    expect(Array.from(bytes.slice(0, PRINCIPAL_CREDENTIAL_MAGIC.length))).toEqual(
      Array.from(new TextEncoder().encode(PRINCIPAL_CREDENTIAL_MAGIC)),
    );
    const parsed = parsePrincipalCredential(bytes);
    expect(principalCredentialsEqual(parsed, GENERATED)).toBe(true);
  });

  it('carries the magic marker outside the hex alphabet (prohibited-plaintext scan safety)', () => {
    expect(PRINCIPAL_CREDENTIAL_MAGIC).toMatch(/^[A-Z]+$/);
    expect(PRINCIPAL_CREDENTIAL_MAGIC).not.toMatch(/^[0-9a-fA-F]+$/);
  });

  it('fails closed on truncation, wrong magic, and unknown format version', () => {
    const bytes = serializePrincipalCredential(GENERATED);
    expect(() => parsePrincipalCredential(bytes.slice(1))).toThrow(PrincipalCredentialError);
    const badMagic = Uint8Array.from(bytes);
    badMagic.set(new TextEncoder().encode('XXXXXXX'));
    expect(() => parsePrincipalCredential(badMagic)).toThrow(PrincipalCredentialError);
    const badVersion = Uint8Array.from(bytes);
    badVersion[PRINCIPAL_CREDENTIAL_MAGIC.length] = 0xff;
    expect(() => parsePrincipalCredential(badVersion)).toThrow(PrincipalCredentialError);
  });

  it('detects any field tampering through the equality helper', () => {
    const bytes = serializePrincipalCredential(GENERATED);
    const tampered = Uint8Array.from(bytes);
    tampered[tampered.length - 1] ^= 0xff;
    const parsed = parsePrincipalCredential(tampered);
    expect(principalCredentialsEqual(parsed, GENERATED)).toBe(false);
  });
});

describe('slot addressing and PoP identity', () => {
  it('addresses the KMC slot with the credential user key', () => {
    expect(principalSlotCredentialId(GENERATED)).toBe(GENERATED.userKey);
  });

  it('derives the same Ed25519 PoP key the registry expects from the credential secret', async () => {
    const direct = await derivePopKey(GENERATED.userSecretKey);
    expect(await principalPopPublicKeyHex(GENERATED)).toBe(direct.publicKeyHex);
  });
});

describe('hygiene pins', () => {
  const MODULE_SOURCE = readFileSync(
    resolve(join(__dirname, 'principalCredential.ts')),
    'utf8',
  );

  it('keeps the slot-key label space disjoint from every other key-schedule family', () => {
    expect(MODULE_SOURCE).toContain('sigbash.principal.v1');
    for (const foreign of [
      'sigbash.executioncredential.v1',
      'sigbash.orgprotocol.v1',
      'sigbash.userroot.v1.',
      'sigbash.capability.v1.',
      'sigbash/sdk-pop-ed25519/v1',
    ]) {
      // The foreign prefixes may appear in this comment block only; the
      // derivation code itself must never build one.
      const body = MODULE_SOURCE.slice(MODULE_SOURCE.indexOf('import '));
      expect(body.includes(`'${foreign}`)).toBe(false);
    }
  });

  it('never imports the shared-execution-credential domain', () => {
    expect(MODULE_SOURCE).not.toContain("from './executionCredential'");
    expect(MODULE_SOURCE).toContain('SIGPRINC');
    expect(MODULE_SOURCE).not.toContain('SIGAEXEC1');
  });
});
