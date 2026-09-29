/**
 * The offline verification checklist exercised end to end against a
 * self-consistent synthetic issuance (see __tests__/helpers for the
 * builder): a real Ed25519 issuer key, a real canonical artifact encoding,
 * and a synthetic envelope whose pins match what the bitcoin_psbt adapter
 * re-derives from the fixture PSBT and the client salt. The tamper matrix
 * is the point: every mutation of the transaction, the envelope, the
 * signature, or the metadata must refuse at the stated checklist step —
 * never accept.
 */

import { getPublicKey as ed25519Pubkey } from '@noble/ed25519';
import {
  buildPsbtBytes,
  bytesToHex,
  CREDENTIAL_ID,
  digest,
  EXPIRES_AT,
  ISSUED_AT,
  ISSUER_KID,
  ISSUER_SEED,
  issue,
  SALT,
} from '../__tests__/helpers/authorization-issuance';
import { ensureBitcoinPsbtAdapterRegistered } from './bitcoinPsbtAdapter';
import { LoadedIssuerKeySet } from './issuerKeySet';
import { VerifyAuthorizationOptions, verifyAuthorization } from './verify';

ensureBitcoinPsbtAdapterRegistered();

const ISSUER_PUBLIC = ed25519Pubkey(ISSUER_SEED);

function issuerKeySet(): LoadedIssuerKeySet {
  return {
    doc: {
      version: 1,
      network: 'signet',
      retentionSeconds: 172800,
      keys: [{
        kid: ISSUER_KID,
        pknetwork: 'signet',
        publicKeyHex: bytesToHex(ISSUER_PUBLIC),
        status: 'active',
      }],
    },
    sha384: 'fixture-pin',
    rawBytes: new Uint8Array(0),
    pinned: true,
  };
}

function baseOptions(issuance: ReturnType<typeof issue>): VerifyAuthorizationOptions {
  return {
    authorization: { rawArtifact: issuance.rawArtifact, rawSignature: issuance.rawSignature },
    network: 'signet',
    issuerKeySet: issuerKeySet(),
    subject: buildPsbtBytes(),
    envelope: issuance.envelopeJSON,
    salt: SALT,
    credential: { credentialIdentifier: CREDENTIAL_ID, keyIndex: 0 },
    now: ISSUED_AT + 10,
  };
}

// --- the suite -------------------------------------------------------------

describe('verifyAuthorization — the offline checklist', () => {
  it('accepts an honest issuance with the credential context present', async () => {
    const result = await verifyAuthorization(baseOptions(issue()));
    expect(result.valid).toBe(true);
    expect(result.detail?.scope).toContain('recomputed');
  });

  it('rejects a tampered transaction at stage 2 for every load-bearing field', async () => {
    const issuance = issue();
    const subject = buildPsbtBytes();

    const tamperAt = (offset: number, replacement: number) => {
      const mutated = Uint8Array.from(subject);
      mutated[offset] = replacement;
      return mutated;
    };
    // Offsets inside the fixture PSBT: magic(5), then the global map's
    // keylen(1) key(1) valuelen(1) prefix the unsigned tx — version(4),
    // count(1), txid(32), vout(4), scriptSigLen(1), sequence(4), outCount(1),
    // then the output's value and its script (length prefix + OP_1 ||
    // PUSH32 program).
    const txidOffset = 13;
    const sequenceOffset = 50;
    const outputValueOffset = 55;
    const recipientProgramOffset = outputValueOffset + 8 + 1 + 2;

    const cases: Array<[string, Uint8Array]> = [
      ['output value', tamperAt(outputValueOffset, (subject[outputValueOffset] ^ 0x01))],
      ['recipient script', tamperAt(recipientProgramOffset, (subject[recipientProgramOffset] ^ 0x01))],
      ['outpoint txid', tamperAt(txidOffset, (subject[txidOffset] ^ 0x01))],
      ['sequence', tamperAt(sequenceOffset, (subject[sequenceOffset] ^ 0x01))],
    ];
    for (const [label, mutated] of cases) {
      const result = await verifyAuthorization({ ...baseOptions(issuance), subject: mutated });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('SUBJECT_MISMATCH');
      expect(result.detail?.stage).toBe('2');
      void label;
    }
    // The prevout amount: tampering the witness utxo's value must also move
    // the sighash. From the tail: output separator(1), input separator(1),
    // the sighash entry (keylen+key+valuelen+4 = 7), then the witness-utxo
    // entry (keylen+key+valuelen+value8+scriptLen+script34 = 46) whose value
    // sits at its eighth byte.
    const witnessValueOffset = subject.length - 1 - 1 - 7 - 46;
    const result = await verifyAuthorization({
      ...baseOptions(issuance),
      subject: tamperAt(witnessValueOffset, subject[witnessValueOffset] ^ 0x01),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('SUBJECT_MISMATCH');
  });

  it('rejects when the pinned challenge no longer matches the transaction (stage 1)', async () => {
    const issuance = issue();
    // Tamper the envelope's pinned challenge_e: stage 1's pin aggregate then
    // diverges from the signed subject commitment.
    const envelope = JSON.parse(issuance.envelopeJSON);
    const challenge = envelope.positions[0].bundle.public_inputs.challenge_e as number[];
    challenge[0] ^= 0x01;
    const result = await verifyAuthorization({
      ...baseOptions(issuance), envelope: JSON.stringify(envelope),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('SUBJECT_MISMATCH');
    expect(result.detail?.stage).toBe('1');
  });

  it('says SUBJECT_CHECK_UNAVAILABLE when the salt or the raw subject is missing', async () => {
    const issuance = issue();
    const noSalt = await verifyAuthorization({ ...baseOptions(issuance), salt: undefined });
    expect(noSalt).toMatchObject({ valid: false, reason: 'SUBJECT_CHECK_UNAVAILABLE' });
    expect(noSalt.detail?.stage).toBe('2');

    const noSubject = await verifyAuthorization({
      ...baseOptions(issuance), subject: undefined,
    });
    expect(noSubject).toMatchObject({ valid: false, reason: 'SUBJECT_CHECK_UNAVAILABLE' });
  });

  it('verifies the signature over the EXACT received bytes and refuses garbage first', async () => {
    const issuance = issue();
    // A flipped signature byte: AUTHORIZATION_BAD_SIGNATURE, not acceptance.
    const badSig = Uint8Array.from(issuance.rawSignature);
    badSig[10] ^= 0x01;
    const result = await verifyAuthorization({
      ...baseOptions(issuance),
      authorization: { rawArtifact: issuance.rawArtifact, rawSignature: badSig },
    });
    expect(result).toMatchObject({ valid: false, reason: 'AUTHORIZATION_BAD_SIGNATURE' });

    // Trailing garbage on the artifact refuses at the decode step, BEFORE any
    // acceptance — even though the signature bytes are untouched.
    const padded = new Uint8Array([...issuance.rawArtifact, 0x00]);
    const paddedResult = await verifyAuthorization({
      ...baseOptions(issuance),
      authorization: { rawArtifact: padded, rawSignature: issuance.rawSignature },
    });
    expect(paddedResult).toMatchObject({ valid: false, reason: 'AUTHORIZATION_NON_CANONICAL' });
    expect(paddedResult.detail?.step).toBe('2');
  });

  it('refuses an artifact the issuer signed with a scope outside the credential', async () => {
    const wrongScopeIssuance = issue({ scope: digest('other-scope') });
    const result = await verifyAuthorization(baseOptions(wrongScopeIssuance));
    expect(result).toMatchObject({ valid: false, reason: 'SCOPE_MISMATCH' });
    expect(result.detail?.step).toBe('7');
  });

  it('refuses a verifier-supplied expected scope that disagrees', async () => {
    const result = await verifyAuthorization({
      ...baseOptions(issue()),
      credential: undefined,
      expectedScope: digest('not-my-scope'),
    });
    expect(result).toMatchObject({ valid: false, reason: 'SCOPE_MISMATCH' });
  });

  it('says NOT CHECKED in the detail when no credential context exists', async () => {
    const result = await verifyAuthorization({
      ...baseOptions(issue()), credential: undefined,
    });
    expect(result.valid).toBe(true);
    expect(result.detail?.scope).toContain('NOT CHECKED');
  });

  it('enforces the validity window and the network against the enforcer', async () => {
    const early = await verifyAuthorization({
      ...baseOptions(issue()), now: ISSUED_AT - 1,
    });
    expect(early).toMatchObject({ valid: false, reason: 'AUTHORIZATION_NOT_YET_VALID' });

    const late = await verifyAuthorization({
      ...baseOptions(issue()), now: EXPIRES_AT + 1,
    });
    expect(late).toMatchObject({ valid: false, reason: 'AUTHORIZATION_EXPIRED' });

    const wrongNetwork = await verifyAuthorization({
      ...baseOptions(issue()), network: 'mainnet',
    });
    expect(wrongNetwork).toMatchObject({ valid: false, reason: 'NETWORK_MISMATCH' });
  });

  it('refuses an unknown issuer kid, a missing key set, and a rejected strength', async () => {
    const unknownKid = await verifyAuthorization(
      baseOptions(issue({ kid: 'authz-ed25519-v1.9' })));
    expect(unknownKid).toMatchObject({ valid: false, reason: 'ISSUER_UNKNOWN' });

    const noKeySet = await verifyAuthorization({
      ...baseOptions(issue()),
      issuerKeySet: undefined,
    });
    expect(noKeySet).toMatchObject({ valid: false, reason: 'ISSUER_UNKNOWN' });
    expect(noKeySet.detail?.step).toBe('1');

    const strength = await verifyAuthorization({
      ...baseOptions(issue()),
      acceptedStrengths: ['hardware_enforced'],
    });
    expect(strength).toMatchObject({ valid: false, reason: 'STRENGTH_REJECTED' });
  });

  it('refuses a subject kind no adapter verifies, via the parse refusal', async () => {
    const result = await verifyAuthorization({
      ...baseOptions(issue()), subject: new Uint8Array(2),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('SUBJECT_MISMATCH');
  });
});
