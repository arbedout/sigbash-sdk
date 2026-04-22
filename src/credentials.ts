/**
 * Credential generation and identity utilities.
 *
 * generateCredentials() — Node.js only. Generates a fresh (apiKey, userKey,
 * userSecretKey) triplet and writes it to a .env file. Safe to call repeatedly:
 * if the file already contains all three keys the existing values are returned
 * unchanged.
 *
 * getAuthHash() — Universal. Returns the hashes the Sigbash server knows for
 * a given credential pair. Share apikeyHash with Sigbash to identify your org
 * (e.g. when requesting mainnet access).
 */

import { doubleSha256 } from './auth';
import { detectEnvironment } from './environment';

// ── Types ──────────────────────────────────────────────────────────────────

export interface GenerateCredentialsOptions {
  /** Path to the .env file. Defaults to '.env' in the current working directory. */
  envPath?: string;
  /** Overwrite an existing .env file. Defaults to false. */
  force?: boolean;
}

export interface GeneratedCredentials {
  apiKey: string;
  userKey: string;
  userSecretKey: string;
  /** Absolute path of the .env file that was written or read. */
  envPath: string;
  /** True if credentials were loaded from an existing file rather than generated fresh. */
  existed: boolean;
}

export interface AuthHashResult {
  /** DSHA256(apiKey + userKey) — identifies this user in the Sigbash server DB. */
  authHash: string;
  /** DSHA256(apiKey + apiKey) — identifies your organisation. Share this with Sigbash
   *  when requesting mainnet access or other org-level changes. */
  apikeyHash: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function randomHex32(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function parseEnvFile(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) continue;
    result[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return result;
}

// ── generateCredentials ────────────────────────────────────────────────────

/**
 * Generate a fresh Sigbash credential triplet and write it to a .env file.
 *
 * If the file already exists and contains SIGBASH_API_KEY, SIGBASH_USER_KEY,
 * and SIGBASH_SECRET_KEY, the existing values are returned with `existed: true`
 * — no file is modified. Pass `force: true` to regenerate and overwrite.
 *
 * Node.js only. Throws in browser/Electron environments.
 *
 * @example
 * const creds = await generateCredentials();
 * if (creds.existed) {
 *   console.log('Loaded existing credentials from', creds.envPath);
 * } else {
 *   console.log('Generated new credentials at', creds.envPath);
 * }
 */
export async function generateCredentials(
  options: GenerateCredentialsOptions = {}
): Promise<GeneratedCredentials> {
  if (detectEnvironment() !== 'node') {
    throw new Error(
      'generateCredentials() is only available in Node.js. ' +
      'In browser environments, construct your SigbashClientOptions manually.'
    );
  }

  const { fs, path } = await import('node:fs/promises').then(async fsModule => ({
    fs: fsModule,
    path: await import('node:path'),
  }));

  const envPath = options.envPath
    ? path.resolve(options.envPath)
    : path.resolve(process.cwd(), '.env');

  // Check for existing credentials unless force-overwriting.
  if (!options.force) {
    try {
      const content = await fs.readFile(envPath, 'utf8');
      const env = parseEnvFile(content);
      const apiKey      = env['SIGBASH_API_KEY'];
      const userKey     = env['SIGBASH_USER_KEY'];
      const userSecretKey = env['SIGBASH_SECRET_KEY'];

      if (apiKey && userKey && userSecretKey) {
        return { apiKey, userKey, userSecretKey, envPath, existed: true };
      }

      const missing = ['SIGBASH_API_KEY', 'SIGBASH_USER_KEY', 'SIGBASH_SECRET_KEY']
        .filter(k => !env[k])
        .join(', ');
      throw new Error(
        `${envPath} exists but is missing required keys: ${missing}. ` +
        'Add them manually or pass { force: true } to regenerate the file.'
      );
    } catch (err: unknown) {
      // File not found → fall through to generation.
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
  }

  const apiKey        = randomHex32();
  const userKey       = randomHex32();
  const userSecretKey = randomHex32();

  const content = [
    `SIGBASH_API_KEY=${apiKey}`,
    `SIGBASH_USER_KEY=${userKey}`,
    `SIGBASH_SECRET_KEY=${userSecretKey}`,
    `SIGBASH_SERVER_URL=https://www.sigbash.com`,
  ].join('\n') + '\n';

  await fs.writeFile(envPath, content, { encoding: 'utf8', flag: 'w' });

  return { apiKey, userKey, userSecretKey, envPath, existed: false };
}

// ── getAuthHash ────────────────────────────────────────────────────────────

/**
 * Compute the Sigbash server-facing identity hashes for a credential pair.
 *
 * - `authHash`   — DSHA256(apiKey + userKey): identifies this specific user.
 * - `apikeyHash` — DSHA256(apiKey + apiKey): identifies your organisation.
 *
 * Share `apikeyHash` with Sigbash when requesting mainnet access or other
 * org-level changes. Neither hash reveals your userSecretKey or any KEK.
 *
 * Works in all environments (Node.js, browser, Electron).
 *
 * @example
 * const { apikeyHash } = await getAuthHash(apiKey, userKey);
 * console.log('Your org identifier:', apikeyHash);
 * console.log('Email support@sigbash.com with this hash to request mainnet access.');
 */
export async function getAuthHash(apiKey: string, userKey: string): Promise<AuthHashResult> {
  const [authHash, apikeyHash] = await Promise.all([
    doubleSha256(apiKey, userKey),
    doubleSha256(apiKey, apiKey),
  ]);
  return { authHash, apikeyHash };
}
