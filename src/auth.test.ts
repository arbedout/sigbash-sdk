import { doubleSha256, validateAuthHash } from './auth';

describe('doubleSha256', () => {
  it('returns the precomputed hash for empty strings', async () => {
    const result = await doubleSha256('', '');
    expect(result).toBe('5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456');
  });

  it('returns the precomputed hash for abc and xyz', async () => {
    const result = await doubleSha256('abc', 'xyz');
    expect(result).toBe('af98a23d6ac410357b5ddeea8881b507b849afc93371c5e2a35ad98aa067c007');
  });

  it('returns a 64-character lowercase hex string', async () => {
    const result = await doubleSha256('hello', 'world');
    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is non-commutative: doubleSha256(a, b) differs from doubleSha256(b, a)', async () => {
    const ab = await doubleSha256('abc', 'xyz');
    const ba = await doubleSha256('xyz', 'abc');
    expect(ab).not.toBe(ba);
  });
});

describe('validateAuthHash', () => {
  it('accepts a valid 64-character lowercase hex string', () => {
    const valid = 'af98a23d6ac410357b5ddeea8881b507b849afc93371c5e2a35ad98aa067c007';
    expect(validateAuthHash(valid)).toBe(true);
  });

  it('rejects a 63-character string', () => {
    const short = 'af98a23d6ac410357b5ddeea8881b507b849afc93371c5e2a35ad98aa067c00';
    expect(validateAuthHash(short)).toBe(false);
  });

  it('rejects a 65-character string', () => {
    const long = 'af98a23d6ac410357b5ddeea8881b507b849afc93371c5e2a35ad98aa067c0070';
    expect(validateAuthHash(long)).toBe(false);
  });

  it('rejects uppercase hex characters', () => {
    const upper = 'AF98A23D6AC410357B5DDEEA8881B507B849AFC93371C5E2A35AD98AA067C007';
    expect(validateAuthHash(upper)).toBe(false);
  });

  it('rejects non-hex characters', () => {
    const nonHex = 'zf98a23d6ac410357b5ddeea8881b507b849afc93371c5e2a35ad98aa067c007';
    expect(validateAuthHash(nonHex)).toBe(false);
  });
});
