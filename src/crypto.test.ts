import { deriveKEK, encryptKMC, decryptKMC } from './crypto';
import { CryptoError } from './errors';

const API_KEY = 'test-api-key';
const USER_KEY = 'test-user-key';
const USER_SECRET_KEY = 'test-user-secret-key';

describe('deriveKEK', () => {
  it('scenario 1: returns a CryptoKey with algorithm name AES-GCM', async () => {
    const kek = await deriveKEK(API_KEY, USER_KEY, USER_SECRET_KEY);
    expect(kek.algorithm.name).toBe('AES-GCM');
  });
});

describe('encryptKMC / decryptKMC roundtrip', () => {
  let kek: CryptoKey;

  beforeAll(async () => {
    kek = await deriveKEK(API_KEY, USER_KEY, USER_SECRET_KEY);
  });

  it('scenario 2: roundtrip short plaintext', async () => {
    const original = 'hello, sigbash!';
    const plainBytes = new TextEncoder().encode(original);
    const encrypted = await encryptKMC(plainBytes, kek);
    const decrypted = await decryptKMC(encrypted, kek);
    expect(new TextDecoder().decode(decrypted)).toBe(original);
  });

  it('scenario 3: roundtrip large (~10 KB) Uint8Array', async () => {
    const original = new Uint8Array(10_000);
    for (let i = 0; i < original.length; i++) {
      original[i] = i % 256;
    }
    const encrypted = await encryptKMC(original, kek);
    const decrypted = await decryptKMC(encrypted, kek);
    expect(decrypted).toEqual(original);
  });

  it('scenario 4: roundtrip empty plaintext', async () => {
    const original = new Uint8Array(0);
    const encrypted = await encryptKMC(original, kek);
    const decrypted = await decryptKMC(encrypted, kek);
    expect(decrypted).toEqual(original);
  });

  it('scenario 5: two encryptKMC calls on same plaintext produce different base64 output (random IV)', async () => {
    const plainBytes = new TextEncoder().encode('same plaintext');
    const encrypted1 = await encryptKMC(plainBytes, kek);
    const encrypted2 = await encryptKMC(plainBytes, kek);
    expect(encrypted1).not.toBe(encrypted2);
  });
});

describe('decryptKMC error cases', () => {
  let userKek: CryptoKey;

  beforeAll(async () => {
    userKek = await deriveKEK(API_KEY, USER_KEY, USER_SECRET_KEY);
  });

  it('scenario 6: wrong userSecretKey (empty string) → different KEK → decrypt fails with CryptoError', async () => {
    const plainBytes = new TextEncoder().encode('user secret data');
    const encrypted = await encryptKMC(plainBytes, userKek);

    const adminKek = await deriveKEK(API_KEY, USER_KEY, '');
    await expect(decryptKMC(encrypted, adminKek)).rejects.toThrow(CryptoError);
  });

  it('scenario 7: different userSecretKey → different KEK → decryptKMC throws CryptoError', async () => {
    const plainBytes = new TextEncoder().encode('some kmc data');
    const encrypted = await encryptKMC(plainBytes, userKek);

    const otherKek = await deriveKEK(API_KEY, USER_KEY, 'completely-different-secret');
    await expect(decryptKMC(encrypted, otherKek)).rejects.toThrow(CryptoError);
  });

  it('scenario 8: decryptKMC with wrong key → CryptoError', async () => {
    const plainBytes = new TextEncoder().encode('some kmc data');
    const encrypted = await encryptKMC(plainBytes, userKek);

    const wrongKek = await deriveKEK('wrong-api-key', 'wrong-user-key', 'wrong-secret');
    await expect(decryptKMC(encrypted, wrongKek)).rejects.toThrow(CryptoError);
  });

  it('scenario 9: decryptKMC with invalid base64 string → CryptoError', async () => {
    await expect(decryptKMC('!!!not-base64!!!', userKek)).rejects.toThrow(CryptoError);
  });

  it('scenario 10: decryptKMC with payload too short (5 bytes, less than 12-byte IV) → CryptoError', async () => {
    const tooShort = btoa(String.fromCharCode(1, 2, 3, 4, 5));
    await expect(decryptKMC(tooShort, userKek)).rejects.toThrow(CryptoError);
  });
});
