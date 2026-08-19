/**
 * Tests for generateCredentials() file handling.
 */

import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { generateCredentials } from './credentials';

describe('generateCredentials', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sigbash-creds-test-'));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('writes .env with owner-only permissions (0600)', async () => {
    const envPath = path.join(tmpDir, '.env');
    await generateCredentials({ envPath });

    const stat = await fs.stat(envPath);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('tightens permissions on an existing world-readable .env when overwritten', async () => {
    const envPath = path.join(tmpDir, '.env');
    await fs.writeFile(envPath, 'SIGBASH_API_KEY=x\n', { mode: 0o644 });

    await generateCredentials({ envPath, force: true });

    const stat = await fs.stat(envPath);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('generates a fresh 64-char hex triplet', async () => {
    const envPath = path.join(tmpDir, '.env');
    const creds = await generateCredentials({ envPath });

    expect(creds.existed).toBe(false);
    for (const key of [creds.apiKey, creds.userKey, creds.userSecretKey]) {
      expect(key).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});
