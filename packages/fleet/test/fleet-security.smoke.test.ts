import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  validateFleetToken,
  readTokenFile,
  FleetConfigError,
} from '../src/security/fleet-token.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('Fleet Security Smoke Suite (DEV-8)', () => {
  it('validateFleetToken correctly classifies token candidates without leaking input', () => {
    // 1. Empty / non-string
    expect(validateFleetToken('')).toEqual({ ok: false, reason: 'EMPTY' });
    expect(validateFleetToken(undefined)).toEqual({ ok: false, reason: 'EMPTY' });

    // 2. Too short (< 24 chars)
    expect(validateFleetToken('short-token-123')).toEqual({ ok: false, reason: 'TOO_SHORT' });

    // 3. Too long (> 512 chars)
    expect(validateFleetToken('a'.repeat(513))).toEqual({ ok: false, reason: 'TOO_LONG' });

    // 4. Invalid characters (spaces, newlines, control, unicode)
    expect(validateFleetToken('valid-length-token-with a space')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });
    expect(validateFleetToken('valid-length-token-with\nnewline')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });
    expect(validateFleetToken('valid-length-token-with-üñíçødé')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });

    // 5. Valid printable ASCII tokens (24 to 512 chars, no spaces)
    expect(validateFleetToken('a'.repeat(24))).toEqual({ ok: true });
    expect(validateFleetToken('a'.repeat(512))).toEqual({ ok: true });
    expect(validateFleetToken('secureship_fleet_token_base64url_1234567890')).toEqual({ ok: true });
  });

  it('readTokenFile rejects UTF-16 BOM and null bytes with clear error', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-smoke-'));
    try {
      // 1. UTF-16 LE BOM (FF FE)
      const utf16LeFile = path.join(tempDir, 'token-utf16le.txt');
      fs.writeFileSync(utf16LeFile, Buffer.from([0xff, 0xfe, 0x61, 0x00, 0x62, 0x00]));

      await expect(readTokenFile(utf16LeFile)).rejects.toThrow(FleetConfigError);
      await expect(readTokenFile(utf16LeFile)).rejects.toThrow(
        /contains UTF-16 encoding or null bytes/i
      );

      // 2. Embedded null byte
      const nullByteFile = path.join(tempDir, 'token-null.txt');
      fs.writeFileSync(nullByteFile, Buffer.from('token-with-\x00-null-byte-1234567890'));

      await expect(readTokenFile(nullByteFile)).rejects.toThrow(FleetConfigError);
      await expect(readTokenFile(nullByteFile)).rejects.toThrow(
        /contains UTF-16 encoding or null bytes/i
      );

      // 3. Valid UTF-8 file with trailing newline
      const validFile = path.join(tempDir, 'valid-token.txt');
      fs.writeFileSync(validFile, 'valid-fleet-secret-token-1234567890\r\n', 'utf8');

      const token = await readTokenFile(validFile);
      expect(token).toBe('valid-fleet-secret-token-1234567890');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('standalone CLI never prints ambient canary FLEET_TOKEN to stdout or stderr', async () => {
    const canaryToken = 'CANARY_FLEET_TOKEN_DO_NOT_LOG_9876543210_XYZ';
    const cliPath = path.resolve(__dirname, '../dist/cli.js');

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-cli-smoke-'));
    const tempDb = path.join(tempDir, 'fleet-db.json');

    const proc = spawn(process.execPath, [cliPath, '0'], {
      env: {
        ...process.env,
        FLEET_TOKEN: canaryToken,
        FLEET_DATA: tempDb,
        FLEET_HOST: '127.0.0.1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdoutData = '';
    let stderrData = '';

    proc.stdout.on('data', (d) => {
      stdoutData += d.toString();
    });
    proc.stderr.on('data', (d) => {
      stderrData += d.toString();
    });

    // Wait for server to start and print banner
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`Timeout waiting for fleet CLI banner. Output: ${stdoutData}`));
      }, 8000);

      const check = setInterval(() => {
        if (stdoutData.includes('SecureShip Fleet: Enterprise CISO Cockpit')) {
          clearInterval(check);
          clearTimeout(timeout);
          resolve();
        }
      }, 50);
    });

    // Kill process
    proc.kill('SIGINT');
    await new Promise((r) => setTimeout(r, 200));
    try {
      proc.kill('SIGKILL');
    } catch {}

    // Verify token secrecy invariant (I1)
    expect(stdoutData).not.toContain(canaryToken);
    expect(stderrData).not.toContain(canaryToken);

    // Verify banner prints source label, not raw token
    expect(stdoutData).toContain(
      'Auth           : required (source: FLEET_TOKEN environment variable)'
    );
    expect(stdoutData).not.toContain('Auth Token     :');

    fs.rmSync(tempDir, { recursive: true, force: true });
  });
});
