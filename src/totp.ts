/**
 * TOTP (Time-based One-Time Password) utilities — RFC 6238 / RFC 4648.
 *
 * Provides secret generation and OTP auth URI construction for
 * 2FA-enabled policy keys.
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Generate a 20-byte TOTP shared secret encoded as base32 (RFC 4648, no padding).
 *
 * @returns Base32-encoded TOTP secret string
 */
export function generateTOTPSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let result = '';
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return result;
}

/**
 * Build an `otpauth://totp/...` URI compatible with standard authenticator apps
 * (Google Authenticator, Authy, etc.).
 *
 * @param secret  - Base32-encoded TOTP secret from generateTOTPSecret()
 * @param userKey - User identifier label shown in the authenticator app
 * @param issuer  - Issuer name shown in the authenticator app (default: 'Sigbash')
 * @returns Full otpauth URI string
 */
export function buildTOTPUri(secret: string, userKey: string, issuer = 'Sigbash'): string {
  const label = encodeURIComponent(`${issuer}:${userKey}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params}`;
}
