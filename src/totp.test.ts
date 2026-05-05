import { generateTOTPSecret, buildTOTPUri } from './totp';

describe('generateTOTPSecret', () => {
  it('1: returns only base32 characters [A-Z2-7]', () => {
    const secret = generateTOTPSecret();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
  });

  it('2: output is exactly 32 characters (encodes 20 bytes)', () => {
    const secret = generateTOTPSecret();
    expect(secret).toHaveLength(32);
  });

  it('3: two calls produce different secrets', () => {
    const a = generateTOTPSecret();
    const b = generateTOTPSecret();
    expect(a).not.toBe(b);
  });
});

describe('buildTOTPUri', () => {
  const secret = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  const userKey = 'testuser';

  it('4: URI starts with otpauth://totp/', () => {
    const uri = buildTOTPUri(secret, userKey);
    expect(uri.startsWith('otpauth://totp/')).toBe(true);
  });

  it('5: URI contains secret= param', () => {
    const uri = buildTOTPUri(secret, userKey);
    expect(uri).toContain('secret=');
  });

  it('6: URI contains algorithm=SHA1, digits=6, period=30', () => {
    const uri = buildTOTPUri(secret, userKey);
    expect(uri).toContain('algorithm=SHA1');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
  });

  it('7: default issuer is Sigbash', () => {
    const uri = buildTOTPUri(secret, userKey);
    expect(uri).toContain('Sigbash');
  });

  it('8: custom issuer overrides Sigbash', () => {
    const uri = buildTOTPUri(secret, userKey, 'MyApp');
    expect(uri).toContain('MyApp');
    expect(uri).not.toContain('Sigbash');
  });

  it('9: userKey is URL-encoded in the label path portion', () => {
    const uri = buildTOTPUri(secret, 'user@test');
    const label = uri.slice('otpauth://totp/'.length, uri.indexOf('?'));
    expect(label).toContain('user%40test');
  });
});
