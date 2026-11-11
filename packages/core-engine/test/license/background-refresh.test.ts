import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  isNearExpiry,
  refreshLicenseInBackground,
  resolveTierCapabilities,
  type ResolvedTierState,
} from '../../src/license/tier-resolver.js';
import { readLicenseFile, writeLicenseFile } from '../../src/license/license-storage.js';
import {
  verifyLicenseJwt,
  buildTierCapabilitiesFromPayload,
} from '../../src/license/license-validator.js';
import {
  SERVER_KEYS,
  ATTACKER_KEYS,
  signWith,
  createTestPayload,
  setupLicenseFile,
  createDeferred,
  createFetchSpy,
} from './jwt-fixtures.js';
import {
  LicenseWorker,
  type Env,
  type LicenseRecord,
  type ServerJwtPayload,
} from '../../../license-server/src/worker.js';

describe('Background JWT Refresh & Expiry Thresholds (Task 1 & 5)', () => {
  let tempDir: string;
  let licenseFilePath: string;
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-refresh-test-'));
    licenseFilePath = path.join(tempDir, 'license.jwt');
    vi.restoreAllMocks();
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    expect(globalThis.fetch).toBe(originalFetch);
  });

  // F1: Baseline tests 100% byte-for-byte identical to baseline commit 70c3087b
  it('isNearExpiry() returns true when exp is 3 days from now', () => {
    const now = new Date('2026-01-10T12:00:00Z');
    const threeDaysFromNowSec = Math.floor(now.getTime() / 1000) + 3 * 24 * 60 * 60;
    expect(isNearExpiry(threeDaysFromNowSec, now)).toBe(true);
  });

  it('isNearExpiry() returns false when exp is 30 days from now', () => {
    const now = new Date('2026-01-10T12:00:00Z');
    const thirtyDaysFromNowSec = Math.floor(now.getTime() / 1000) + 30 * 24 * 60 * 60;
    expect(isNearExpiry(thirtyDaysFromNowSec, now)).toBe(false);
  });

  it('isNearExpiry() returns false when JWT is already expired', () => {
    const now = new Date('2026-01-10T12:00:00Z');
    const fiveDaysAgoSec = Math.floor(now.getTime() / 1000) - 5 * 24 * 60 * 60;
    expect(isNearExpiry(fiveDaysAgoSec, now)).toBe(false);
  });

  // ============================================================================
  // LAYER A: Request shape and pre-flight guards (fetch mocked)
  // ============================================================================
  describe('LAYER A: Request Shape & Pre-Flight Guards', () => {
    it('A1: Exactly one fetch call, GET method, url /v1/validate, headers, redirect error, signal', async () => {
      const now = Math.floor(Date.now() / 1000);
      const file = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const fetchSpy = createFetchSpy();

      await refreshLicenseInBackground(file.path, file.jwt, 'https://license.secureship.dev', {
        publicKeyPem: SERVER_KEYS.publicKey,
        now,
      });

      expect(fetchSpy.calls.length).toBe(1);
      const call = fetchSpy.calls[0]!;
      expect(call.url).toBe('https://license.secureship.dev/v1/validate');
      expect(call.init?.method).toBe('GET');
      expect(call.init?.headers).toEqual({
        Authorization: `Bearer ${file.jwt}`,
        Accept: 'application/json',
      });
      expect(call.init?.body).toBeUndefined();
      expect(call.init?.redirect).toBe('error');
      expect(call.init?.signal).toBeInstanceOf(AbortSignal);
    });

    it('A2: Token with trailing newline and whitespace is sent trimmed', async () => {
      const now = Math.floor(Date.now() / 1000);
      const file = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const paddedJwt = `  \n\r  ${file.jwt}  \r\n  `;
      writeLicenseFile(paddedJwt, file.path);
      const fetchSpy = createFetchSpy();

      await refreshLicenseInBackground(file.path, paddedJwt, 'https://license.secureship.dev', {
        publicKeyPem: SERVER_KEYS.publicKey,
        now,
      });

      expect(fetchSpy.calls.length).toBe(1);
      expect(fetchSpy.calls[0]!.init?.headers).toEqual({
        Authorization: `Bearer ${file.jwt}`,
        Accept: 'application/json',
      });
    });

    it('A3: Trailing slashes on serverUrl produce canonical URL, omitted serverUrl defaults to https://license.secureship.dev', async () => {
      const now = Math.floor(Date.now() / 1000);
      const file = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const fetchSpy = createFetchSpy();

      // Case 1: single trailing slash
      await refreshLicenseInBackground(file.path, file.jwt, 'https://license.secureship.dev/', {
        publicKeyPem: SERVER_KEYS.publicKey,
        now,
      });
      expect(fetchSpy.calls.length).toBe(1);
      expect(fetchSpy.calls[0]!.url).toBe('https://license.secureship.dev/v1/validate');

      // Case 2: multiple trailing slashes
      await refreshLicenseInBackground(file.path, file.jwt, 'https://license.secureship.dev///', {
        publicKeyPem: SERVER_KEYS.publicKey,
        now,
      });
      expect(fetchSpy.calls.length).toBe(2);
      expect(fetchSpy.calls[1]!.url).toBe('https://license.secureship.dev/v1/validate');

      // Case 3: omitted serverUrl
      await refreshLicenseInBackground(file.path, file.jwt, undefined, {
        publicKeyPem: SERVER_KEYS.publicKey,
        now,
      });
      expect(fetchSpy.calls.length).toBe(3);
      expect(fetchSpy.calls[2]!.url).toBe('https://license.secureship.dev/v1/validate');
    });

    it('A4: Timeout aborts fetch at 5000ms (default) and custom timeoutMs, clears timer on success and failure', async () => {
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
      try {
        const now = Math.floor(Date.now() / 1000);
        const file = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });

        let aborted = false;
        const hangingFetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
          return new Promise((_resolve, reject) => {
            if (init?.signal) {
              init.signal.addEventListener('abort', () => {
                aborted = true;
                const err = new Error('The operation was aborted');
                err.name = 'AbortError';
                reject(err);
              });
            }
          });
        });
        vi.stubGlobal('fetch', hangingFetch);

        const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');

        // Part 1: default 5000ms timeout
        const promise1 = refreshLicenseInBackground(
          file.path,
          file.jwt,
          'https://license.secureship.dev',
          { publicKeyPem: SERVER_KEYS.publicKey, now }
        );
        expect(aborted).toBe(false);
        vi.advanceTimersByTime(5000);
        await promise1;
        expect(aborted).toBe(true);
        expect(fs.readFileSync(file.path, 'utf-8')).toBe(file.jwt);
        expect(clearTimeoutSpy).toHaveBeenCalled();

        // Part 2: custom timeoutMs (2500ms)
        aborted = false;
        const promise2 = refreshLicenseInBackground(
          file.path,
          file.jwt,
          'https://license.secureship.dev',
          { publicKeyPem: SERVER_KEYS.publicKey, timeoutMs: 2500, now }
        );
        vi.advanceTimersByTime(2499);
        expect(aborted).toBe(false);
        vi.advanceTimersByTime(1);
        await promise2;
        expect(aborted).toBe(true);

        // Part 3: timer cleared on success
        clearTimeoutSpy.mockClear();
        const successFetch = vi.fn().mockResolvedValue(
          new Response(JSON.stringify({ valid: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        );
        vi.stubGlobal('fetch', successFetch);

        await refreshLicenseInBackground(file.path, file.jwt, 'https://license.secureship.dev', {
          publicKeyPem: SERVER_KEYS.publicKey,
          now,
        });
        expect(clearTimeoutSpy).toHaveBeenCalled();
      } finally {
        vi.useRealTimers();
      }
    });

    it('A5: Table-driven no-network pre-flight guards result in 0 fetch calls', async () => {
      const now = Math.floor(Date.now() / 1000);
      const validFile = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const expiredFile = setupLicenseFile(tempDir, { exp: now - 3600 }, SERVER_KEYS.privateKey);
      const attackerSignedFile = setupLicenseFile(
        tempDir,
        { exp: now + 3 * 86400 },
        ATTACKER_KEYS.privateKey
      );

      const fetchMock = vi.fn();
      vi.stubGlobal('fetch', fetchMock);

      const guardCases: Array<{
        label: string;
        jwt: string;
        serverUrl: string;
        path: string;
      }> = [
        // Stale-caller argument shape (email instead of JWT)
        {
          label: 'stale-caller email string',
          jwt: 'user@enterprise.com',
          serverUrl: 'https://license.secureship.dev',
          path: validFile.path,
        },
        {
          label: 'non-string JWT',
          jwt: 12345 as unknown as string,
          serverUrl: 'https://license.secureship.dev',
          path: validFile.path,
        },
        {
          label: 'non-string licensePath',
          jwt: validFile.jwt,
          serverUrl: 'https://license.secureship.dev',
          path: null as unknown as string,
        },
        {
          label: 'empty licensePath',
          jwt: validFile.jwt,
          serverUrl: 'https://license.secureship.dev',
          path: '   ',
        },
        // Empty or whitespace JWT
        {
          label: 'empty string JWT',
          jwt: '',
          serverUrl: 'https://license.secureship.dev',
          path: validFile.path,
        },
        {
          label: 'whitespace JWT',
          jwt: '   \n\t  ',
          serverUrl: 'https://license.secureship.dev',
          path: validFile.path,
        },
        // Malformed segment counts
        {
          label: '2-segment token',
          jwt: 'header.payload',
          serverUrl: 'https://license.secureship.dev',
          path: validFile.path,
        },
        {
          label: '4-segment token',
          jwt: 'seg1.seg2.seg3.seg4',
          serverUrl: 'https://license.secureship.dev',
          path: validFile.path,
        },
        // Non-base64url characters
        {
          label: 'non-base64url characters',
          jwt: 'header.pay!load.sig',
          serverUrl: 'https://license.secureship.dev',
          path: validFile.path,
        },
        // Insecure or invalid server URLs
        {
          label: 'non-loopback http URL',
          jwt: validFile.jwt,
          serverUrl: 'http://evil.example',
          path: validFile.path,
        },
        {
          label: 'ftp URL',
          jwt: validFile.jwt,
          serverUrl: 'ftp://secureship.dev',
          path: validFile.path,
        },
        {
          label: 'malformed not-a-url',
          jwt: validFile.jwt,
          serverUrl: 'not a url',
          path: validFile.path,
        },
        {
          label: 'empty serverUrl',
          jwt: validFile.jwt,
          serverUrl: '',
          path: validFile.path,
        },
        {
          label: 'non-string serverUrl',
          jwt: validFile.jwt,
          serverUrl: 12345 as unknown as string,
          path: validFile.path,
        },
        // Offline pre-verification failures
        {
          label: 'bad signature (ATTACKER key)',
          jwt: attackerSignedFile.jwt,
          serverUrl: 'https://license.secureship.dev',
          path: attackerSignedFile.path,
        },
        {
          label: 'expired current token',
          jwt: expiredFile.jwt,
          serverUrl: 'https://license.secureship.dev',
          path: expiredFile.path,
        },
      ];

      for (const c of guardCases) {
        fetchMock.mockClear();
        await refreshLicenseInBackground(c.path, c.jwt, c.serverUrl, {
          publicKeyPem: SERVER_KEYS.publicKey,
          now,
        });
        expect(fetchMock, `Guard failed for: ${c.label}`).toHaveBeenCalledTimes(0);
      }
    });

    it('A6: Loopback HTTP addresses are permitted and make exactly one call', async () => {
      const now = Math.floor(Date.now() / 1000);
      const file = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const fetchSpy = createFetchSpy();

      // http://localhost:8787
      await refreshLicenseInBackground(file.path, file.jwt, 'http://localhost:8787', {
        publicKeyPem: SERVER_KEYS.publicKey,
        now,
      });
      expect(fetchSpy.calls.length).toBe(1);
      expect(fetchSpy.calls[0]!.url).toBe('http://localhost:8787/v1/validate');

      // http://127.0.0.1:8787
      await refreshLicenseInBackground(file.path, file.jwt, 'http://127.0.0.1:8787', {
        publicKeyPem: SERVER_KEYS.publicKey,
        now,
      });
      expect(fetchSpy.calls.length).toBe(2);
      expect(fetchSpy.calls[1]!.url).toBe('http://127.0.0.1:8787/v1/validate');
    });
  });

  // ============================================================================
  // LAYER B: Response handling and quietness guarantee
  // ============================================================================
  describe('LAYER B: Defensive Response Handling & Invariants', () => {
    let consoleLogSpy: ReturnType<typeof vi.spyOn>;
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;
    let consoleErrorSpy: ReturnType<typeof vi.spyOn>;
    let stdoutSpy: MockInstance;
    let stderrSpy: MockInstance;

    beforeEach(() => {
      consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
      stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    });

    function assertQuiet() {
      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleWarnSpy).not.toHaveBeenCalled();
      expect(consoleErrorSpy).not.toHaveBeenCalled();
      expect(stdoutSpy).not.toHaveBeenCalled();
      expect(stderrSpy).not.toHaveBeenCalled();
    }

    it('B1: Valid refreshed token signed by SERVER leads to file equalling refreshed token byte-for-byte', async () => {
      const now = Math.floor(Date.now() / 1000);
      const current = setupLicenseFile(tempDir, {
        sub: 'dev@company.com',
        orgId: 'org-enterprise',
        exp: now + 3 * 86400,
      });

      const refreshedPayload = createTestPayload({
        sub: 'dev@company.com',
        orgId: 'org-enterprise',
        exp: now + 30 * 86400,
      });
      const refreshedJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        refreshedPayload
      );

      const fetchSpy = createFetchSpy();
      fetchSpy.setJsonResponse({ valid: true, refreshedJwt }, 200);

      await refreshLicenseInBackground(
        current.path,
        current.jwt,
        'https://license.secureship.dev',
        { publicKeyPem: SERVER_KEYS.publicKey, now }
      );

      const diskContent = fs.readFileSync(current.path, 'utf-8');
      expect(diskContent).toBe(refreshedJwt);
      assertQuiet();
    });

    it('B2: Non-OK HTTP statuses (401, 403, 404, 410, 500, 503) leave file unchanged', async () => {
      const now = Math.floor(Date.now() / 1000);
      const statuses = [401, 403, 404, 410, 500, 503];

      for (const status of statuses) {
        const current = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
        const fetchSpy = createFetchSpy();
        const body =
          status === 403
            ? { valid: false, code: 'LICENSE_REVOKED', error: 'License revoked' }
            : { valid: false, error: `Error ${status}` };
        fetchSpy.setJsonResponse(body, status);

        await refreshLicenseInBackground(
          current.path,
          current.jwt,
          'https://license.secureship.dev',
          { publicKeyPem: SERVER_KEYS.publicKey, now }
        );

        expect(fs.readFileSync(current.path, 'utf-8')).toBe(current.jwt);
        assertQuiet();
      }
    });

    it('B3: HTTP 200 with { valid: true } and no refreshedJwt leaves file unchanged', async () => {
      const now = Math.floor(Date.now() / 1000);
      const current = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const fetchSpy = createFetchSpy();
      fetchSpy.setJsonResponse({ valid: true }, 200);

      await refreshLicenseInBackground(
        current.path,
        current.jwt,
        'https://license.secureship.dev',
        { publicKeyPem: SERVER_KEYS.publicKey, now }
      );

      expect(fs.readFileSync(current.path, 'utf-8')).toBe(current.jwt);
      assertQuiet();
    });

    it('B4: HTTP 200 with legacy key { jwt: <token> } leaves file unchanged (regression guard for old protocol)', async () => {
      const now = Math.floor(Date.now() / 1000);
      const current = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const refreshedPayload = createTestPayload({ exp: now + 30 * 86400 });
      const validRefreshedJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        refreshedPayload
      );

      const fetchSpy = createFetchSpy();
      // Legacy protocol response
      fetchSpy.setJsonResponse({ jwt: validRefreshedJwt }, 200);

      await refreshLicenseInBackground(
        current.path,
        current.jwt,
        'https://license.secureship.dev',
        { publicKeyPem: SERVER_KEYS.publicKey, now }
      );

      expect(fs.readFileSync(current.path, 'utf-8')).toBe(current.jwt);
      assertQuiet();
    });

    it('B5: refreshedJwt of wrong types, empty, whitespace, malformed, or > 16384 chars leaves file unchanged', async () => {
      const now = Math.floor(Date.now() / 1000);
      const invalidRefreshedValues = [
        12345,
        null,
        ['token.token.token'],
        { token: 'xyz' },
        '',
        '   \n\t  ',
        'only.two',
        'a'.repeat(16385),
      ];

      for (const val of invalidRefreshedValues) {
        const current = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
        const fetchSpy = createFetchSpy();
        fetchSpy.setJsonResponse({ valid: true, refreshedJwt: val }, 200);

        await refreshLicenseInBackground(
          current.path,
          current.jwt,
          'https://license.secureship.dev',
          { publicKeyPem: SERVER_KEYS.publicKey, now }
        );

        expect(fs.readFileSync(current.path, 'utf-8')).toBe(current.jwt);
        assertQuiet();
      }
    });

    it('B6: Body not JSON, JSON null/array/string, or res.json() throwing leaves file unchanged with no throw', async () => {
      const now = Math.floor(Date.now() / 1000);
      const scenarios: Array<{ label: string; handler: () => Promise<Response> }> = [
        {
          label: 'raw non-JSON string',
          handler: async () =>
            new Response('Bad Gateway: Nginx 502', {
              status: 200,
              headers: { 'Content-Type': 'text/html' },
            }),
        },
        {
          label: 'JSON null',
          handler: async () =>
            new Response('null', {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }),
        },
        {
          label: 'JSON array',
          handler: async () =>
            new Response('["valid", true]', {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }),
        },
        {
          label: 'JSON primitive string',
          handler: async () =>
            new Response('"hello world"', {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }),
        },
        {
          label: 'res.json() throws exception',
          handler: async () =>
            ({
              ok: true,
              status: 200,
              json: async () => {
                throw new Error('Unexpected token in JSON');
              },
            }) as unknown as Response,
        },
      ];

      for (const s of scenarios) {
        const current = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
        const fetchSpy = createFetchSpy();
        fetchSpy.setHandler(s.handler);

        await expect(
          refreshLicenseInBackground(current.path, current.jwt, 'https://license.secureship.dev', {
            publicKeyPem: SERVER_KEYS.publicKey,
            now,
          })
        ).resolves.not.toThrow();

        expect(fs.readFileSync(current.path, 'utf-8')).toBe(current.jwt);
        assertQuiet();
      }
    });

    it('B7: Verification failures leave file unchanged (ATTACKER, tampered, alg none, HS256, expired, equal exp, rollback, sub/orgId mismatch)', async () => {
      const now = Math.floor(Date.now() / 1000);
      const current = setupLicenseFile(tempDir, {
        sub: 'alice@corp.com',
        orgId: 'org-alpha',
        exp: now + 3 * 86400,
      });

      const validFuturePayload = createTestPayload({
        sub: 'alice@corp.com',
        orgId: 'org-alpha',
        exp: now + 30 * 86400,
      });

      // 1. Signed by ATTACKER key
      const attackerJwt = signWith(
        ATTACKER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        validFuturePayload
      );

      // 2. Tampered payload with SERVER signature
      const legitimateJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        validFuturePayload
      );
      const [head, , sig] = legitimateJwt.split('.');
      const tamperedPayloadStr = Buffer.from(
        JSON.stringify({ ...validFuturePayload, seats: 99999 })
      ).toString('base64url');
      const tamperedJwt = `${head}.${tamperedPayloadStr}.${sig}`;

      // 3. alg none
      const algNoneJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'none', kid: 'secureship-2026-01', typ: 'JWT' },
        validFuturePayload
      );

      // 4. HS256 using public key PEM as HMAC secret
      const hs256Jwt = signWith(
        SERVER_KEYS.publicKey,
        { alg: 'HS256', kid: 'secureship-2026-01', typ: 'JWT' },
        validFuturePayload
      );

      // 5. Refreshed token already expired
      const expiredPayload = createTestPayload({
        sub: 'alice@corp.com',
        orgId: 'org-alpha',
        exp: now - 60,
      });
      const expiredJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        expiredPayload
      );

      // 6. Refreshed exp equal to current exp (no forward progression)
      const equalExpPayload = createTestPayload({
        sub: 'alice@corp.com',
        orgId: 'org-alpha',
        exp: current.payload.exp,
      });
      const equalExpJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        equalExpPayload
      );

      // 7. Refreshed exp earlier than current exp (rollback attack)
      const rollbackPayload = createTestPayload({
        sub: 'alice@corp.com',
        orgId: 'org-alpha',
        exp: current.payload.exp - 86400,
      });
      const rollbackJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        rollbackPayload
      );

      // 8. Identity mismatch: different sub
      const diffSubPayload = createTestPayload({
        sub: 'mallory@evil.com',
        orgId: 'org-alpha',
        exp: now + 30 * 86400,
      });
      const diffSubJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        diffSubPayload
      );

      // 9. Identity mismatch: different orgId
      const diffOrgPayload = createTestPayload({
        sub: 'alice@corp.com',
        orgId: 'org-beta',
        exp: now + 30 * 86400,
      });
      const diffOrgJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        diffOrgPayload
      );

      const failureCases = [
        { label: 'signed by ATTACKER', token: attackerJwt },
        { label: 'tampered payload with valid sig', token: tamperedJwt },
        { label: 'alg none', token: algNoneJwt },
        { label: 'HS256 public key secret attack', token: hs256Jwt },
        { label: 'refreshed token expired', token: expiredJwt },
        { label: 'refreshed exp equal to current', token: equalExpJwt },
        { label: 'refreshed exp earlier (rollback replay)', token: rollbackJwt },
        { label: 'different sub identity', token: diffSubJwt },
        { label: 'different orgId identity', token: diffOrgJwt },
      ];

      for (const fc of failureCases) {
        const fetchSpy = createFetchSpy();
        fetchSpy.setJsonResponse({ valid: true, refreshedJwt: fc.token }, 200);

        await refreshLicenseInBackground(
          current.path,
          current.jwt,
          'https://license.secureship.dev',
          { publicKeyPem: SERVER_KEYS.publicKey, now }
        );

        expect(fs.readFileSync(current.path, 'utf-8'), `Failed on: ${fc.label}`).toBe(current.jwt);
        assertQuiet();
      }
    });

    it('B8: Tier change is allowed: a refreshed token for another tier with a later exp is written and verified', async () => {
      const now = Math.floor(Date.now() / 1000);
      const current = setupLicenseFile(tempDir, {
        sub: 'user@corp.com',
        orgId: 'org-123',
        tier: 'PRO_TEAM',
        exp: now + 3 * 86400,
      });

      const upgradedPayload = createTestPayload({
        sub: 'user@corp.com',
        orgId: 'org-123',
        tier: 'ENTERPRISE',
        exp: now + 30 * 86400,
      });
      const upgradedJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        upgradedPayload
      );

      const fetchSpy = createFetchSpy();
      fetchSpy.setJsonResponse({ valid: true, refreshedJwt: upgradedJwt }, 200);

      await refreshLicenseInBackground(
        current.path,
        current.jwt,
        'https://license.secureship.dev',
        { publicKeyPem: SERVER_KEYS.publicKey, now }
      );

      const written = fs.readFileSync(current.path, 'utf-8');
      expect(written).toBe(upgradedJwt);

      const verifyCheck = verifyLicenseJwt(written, SERVER_KEYS.publicKey, now);
      expect(verifyCheck.valid).toBe(true);
      expect(verifyCheck.payload?.tier).toBe('ENTERPRISE');
      assertQuiet();
    });

    it('B9: Compare-and-swap: user modifying license file while request is in flight prevents overwrite', async () => {
      const now = Math.floor(Date.now() / 1000);
      const current = setupLicenseFile(tempDir, {
        sub: 'user@corp.com',
        orgId: 'org-123',
        exp: now + 3 * 86400,
      });

      const refreshedPayload = createTestPayload({
        sub: 'user@corp.com',
        orgId: 'org-123',
        exp: now + 30 * 86400,
      });
      const refreshedJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        refreshedPayload
      );

      const userNewPayload = createTestPayload({
        sub: 'user@corp.com',
        orgId: 'org-123',
        exp: now + 60 * 86400,
      });
      const userNewJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        userNewPayload
      );

      const fetchSpy = createFetchSpy();
      fetchSpy.setHandler(async () => {
        // While request is in flight, the user installs a new license file on disk
        writeLicenseFile(userNewJwt, current.path);
        return new Response(JSON.stringify({ valid: true, refreshedJwt }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      });

      await refreshLicenseInBackground(
        current.path,
        current.jwt,
        'https://license.secureship.dev',
        { publicKeyPem: SERVER_KEYS.publicKey, now }
      );

      // CAS must detect change: file retains user's new JWT, not server's refreshed JWT
      expect(fs.readFileSync(current.path, 'utf-8')).toBe(userNewJwt);
      assertQuiet();
    });

    it('B10: writeLicenseFile failure resolves cleanly with nothing thrown', async () => {
      const now = Math.floor(Date.now() / 1000);
      const file = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });

      const refreshedPayload = createTestPayload({ exp: now + 30 * 86400 });
      const refreshedJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        refreshedPayload
      );

      const fetchSpy = createFetchSpy();
      fetchSpy.setJsonResponse({ valid: true, refreshedJwt }, 200);

      // Make the license file a directory to cause writeLicenseFile (fs.writeFileSync) to fail with EISDIR
      fs.unlinkSync(file.path);
      fs.mkdirSync(file.path);

      await expect(
        refreshLicenseInBackground(file.path, file.jwt, 'https://license.secureship.dev', {
          publicKeyPem: SERVER_KEYS.publicKey,
          now,
        })
      ).resolves.not.toThrow();

      assertQuiet();
    });

    it('B11: Key selection priority: options.publicKeyPem -> process.env.SECURESHIP_PUBLIC_KEY -> SECURESHIP_PUBLIC_KEY_PEM', async () => {
      const now = Math.floor(Date.now() / 1000);
      const customKey = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const current = setupLicenseFile(tempDir, { exp: now + 3 * 86400 }, customKey.privateKey);

      const refreshedPayload = createTestPayload({ exp: now + 30 * 86400 });
      const refreshedJwt = signWith(
        customKey.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        refreshedPayload
      );

      const fetchSpy = createFetchSpy();
      fetchSpy.setJsonResponse({ valid: true, refreshedJwt }, 200);

      // 1. options.publicKeyPem is used
      await refreshLicenseInBackground(
        current.path,
        current.jwt,
        'https://license.secureship.dev',
        { publicKeyPem: customKey.publicKey, now }
      );
      expect(fs.readFileSync(current.path, 'utf-8')).toBe(refreshedJwt);

      // 2. process.env.SECURESHIP_PUBLIC_KEY is used when options is absent
      writeLicenseFile(current.jwt, current.path);
      process.env.SECURESHIP_PUBLIC_KEY = customKey.publicKey;
      try {
        await refreshLicenseInBackground(
          current.path,
          current.jwt,
          'https://license.secureship.dev',
          { now }
        );
        expect(fs.readFileSync(current.path, 'utf-8')).toBe(refreshedJwt);
      } finally {
        delete process.env.SECURESHIP_PUBLIC_KEY;
      }

      // 3. A refresh signed by a key that does not match is rejected
      writeLicenseFile(current.jwt, current.path);
      const otherKey = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      const mismatchJwt = signWith(
        otherKey.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        refreshedPayload
      );
      fetchSpy.setJsonResponse({ valid: true, refreshedJwt: mismatchJwt }, 200);

      await refreshLicenseInBackground(
        current.path,
        current.jwt,
        'https://license.secureship.dev',
        { publicKeyPem: customKey.publicKey, now }
      );
      expect(fs.readFileSync(current.path, 'utf-8')).toBe(current.jwt);
      assertQuiet();
    });

    it('B12: In-flight de-duplication: 5 concurrent calls share 1 fetch, completion allows next fetch, independent paths fetch separately', async () => {
      const now = Math.floor(Date.now() / 1000);
      const file1 = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-dedup-'));
      const file2 = setupLicenseFile(dir2, { exp: now + 3 * 86400 });

      const deferred = createDeferred<Response>();
      const fetchSpy = createFetchSpy();
      fetchSpy.setHandler(async () => deferred.promise);

      try {
        // 1. 5 concurrent calls for file1
        const p1 = refreshLicenseInBackground(
          file1.path,
          file1.jwt,
          'https://license.secureship.dev',
          {
            publicKeyPem: SERVER_KEYS.publicKey,
            now,
          }
        );
        const p2 = refreshLicenseInBackground(
          file1.path,
          file1.jwt,
          'https://license.secureship.dev',
          {
            publicKeyPem: SERVER_KEYS.publicKey,
            now,
          }
        );
        const p3 = refreshLicenseInBackground(
          file1.path,
          file1.jwt,
          'https://license.secureship.dev',
          {
            publicKeyPem: SERVER_KEYS.publicKey,
            now,
          }
        );
        const p4 = refreshLicenseInBackground(
          file1.path,
          file1.jwt,
          'https://license.secureship.dev',
          {
            publicKeyPem: SERVER_KEYS.publicKey,
            now,
          }
        );
        const p5 = refreshLicenseInBackground(
          file1.path,
          file1.jwt,
          'https://license.secureship.dev',
          {
            publicKeyPem: SERVER_KEYS.publicKey,
            now,
          }
        );

        // 2. Concurrently call file2 (different path)
        const pOther = refreshLicenseInBackground(
          file2.path,
          file2.jwt,
          'https://license.secureship.dev',
          {
            publicKeyPem: SERVER_KEYS.publicKey,
            now,
          }
        );

        // Exactly 2 fetch calls initiated: 1 for file1 (deduped across 5 calls), 1 for file2
        expect(fetchSpy.calls.length).toBe(2);

        // Resolve response
        const refreshedPayload = createTestPayload({ exp: now + 30 * 86400 });
        const refreshedJwt = signWith(
          SERVER_KEYS.privateKey,
          { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
          refreshedPayload
        );
        deferred.resolve(
          new Response(JSON.stringify({ valid: true, refreshedJwt }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        );

        await Promise.all([p1, p2, p3, p4, p5, pOther]);

        // 3. Subsequent call after completion initiates a new fetch
        fetchSpy.setJsonResponse({ valid: true, refreshedJwt }, 200);
        await refreshLicenseInBackground(file1.path, file1.jwt, 'https://license.secureship.dev', {
          publicKeyPem: SERVER_KEYS.publicKey,
          now,
        });
        expect(fetchSpy.calls.length).toBe(3);

        // 4. Rejected fetch cleans in-flight map so next call retries
        fetchSpy.setError(new Error('Network disconnect'));
        await refreshLicenseInBackground(file1.path, file1.jwt, 'https://license.secureship.dev', {
          publicKeyPem: SERVER_KEYS.publicKey,
          now,
        });
        expect(fetchSpy.calls.length).toBe(4);

        fetchSpy.setJsonResponse({ valid: true, refreshedJwt }, 200);
        await refreshLicenseInBackground(file1.path, file1.jwt, 'https://license.secureship.dev', {
          publicKeyPem: SERVER_KEYS.publicKey,
          now,
        });
        expect(fetchSpy.calls.length).toBe(5);
      } finally {
        fs.rmSync(dir2, { recursive: true, force: true });
      }
      assertQuiet();
    });
  });

  // ============================================================================
  // LAYER C: Call site (resolveTierCapabilities integration)
  // ============================================================================
  describe('LAYER C: resolveTierCapabilities Call Site Integration', () => {
    it('C1: Near-expiry token with autoRefresh triggers 1 fetch with raw token in Authorization Bearer and updates file on deferred resolve', async () => {
      const now = Math.floor(Date.now() / 1000);
      const file = setupLicenseFile(tempDir, {
        sub: 'lead-dev@organization.com',
        orgId: 'org-enterprise',
        exp: now + 3 * 86400,
      });

      const refreshedPayload = createTestPayload({
        sub: 'lead-dev@organization.com',
        orgId: 'org-enterprise',
        exp: now + 30 * 86400,
      });
      const refreshedJwt = signWith(
        SERVER_KEYS.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        refreshedPayload
      );

      const deferred = createDeferred<Response>();
      const completionLatch = createDeferred<void>();

      const fetchSpy = createFetchSpy();
      fetchSpy.setHandler(async () => {
        const res = await deferred.promise;
        return {
          ok: res.ok,
          status: res.status,
          headers: res.headers,
          json: async () => {
            const data = await res.json();
            // Allow microtasks for writeLicenseFile to run before latch resolves
            queueMicrotask(() => queueMicrotask(() => completionLatch.resolve()));
            return data;
          },
        } as unknown as Response;
      });

      // Synchronous return from resolveTierCapabilities
      const state = await resolveTierCapabilities({
        licensePath: file.path,
        publicKeyPem: SERVER_KEYS.publicKey,
      });

      expect(state.status).toBe('ACTIVE');
      expect(state.tier).toBe('PRO_TEAM');
      expect(fetchSpy.calls.length).toBe(1);
      const firstCall = fetchSpy.calls[0]!;
      expect(firstCall.init?.headers).toEqual({
        Authorization: `Bearer ${file.jwt}`,
        Accept: 'application/json',
      });
      // Crucial: Authorization header must NOT be sub email
      expect(firstCall.init?.headers).not.toEqual(
        expect.objectContaining({ Authorization: 'Bearer lead-dev@organization.com' })
      );

      // Now resolve deferred response and await completion latch
      deferred.resolve(
        new Response(JSON.stringify({ valid: true, refreshedJwt }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );
      await completionLatch.promise;

      expect(fs.readFileSync(file.path, 'utf-8')).toBe(refreshedJwt);
    });

    it('C2: 30-day token, autoRefresh:false, or expired token make 0 fetch calls', async () => {
      const now = Math.floor(Date.now() / 1000);
      const fetchSpy = createFetchSpy();

      // Case 1: 30-day token (not near expiry)
      const freshFile = setupLicenseFile(tempDir, { exp: now + 30 * 86400 });
      const state1 = await resolveTierCapabilities({
        licensePath: freshFile.path,
        publicKeyPem: SERVER_KEYS.publicKey,
      });
      expect(state1.status).toBe('ACTIVE');
      expect(fetchSpy.calls.length).toBe(0);

      // Case 2: near expiry but autoRefresh is false
      const nearFile = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const state2 = await resolveTierCapabilities({
        licensePath: nearFile.path,
        publicKeyPem: SERVER_KEYS.publicKey,
        autoRefresh: false,
      });
      expect(state2.status).toBe('ACTIVE');
      expect(fetchSpy.calls.length).toBe(0);

      // Case 3: expired token
      const expiredFile = setupLicenseFile(tempDir, { exp: now - 3600 });
      const state3 = await resolveTierCapabilities({
        licensePath: expiredFile.path,
        publicKeyPem: SERVER_KEYS.publicKey,
      });
      expect(state3.status).toBe('EXPIRED');
      expect(state3.tier).toBe('FREE_BYOK');
      expect(fetchSpy.calls.length).toBe(0);
    });

    it('C3: Returned ResolvedTierState deep-equals golden object, stderr warning text byte-identical to baseline', async () => {
      const now = Math.floor(Date.now() / 1000);
      const fixedExp = now + 3 * 86400;
      const file = setupLicenseFile(tempDir, {
        sub: 'golden-user@corp.com',
        orgId: 'golden-org',
        tier: 'PRO_TEAM',
        exp: fixedExp,
      });

      let stderrOutput = '';
      const stderrSpy = vi
        .spyOn(process.stderr, 'write')
        .mockImplementation((chunk: string | Uint8Array) => {
          stderrOutput += chunk.toString();
          return true;
        });

      createFetchSpy();

      const result = await resolveTierCapabilities({
        licensePath: file.path,
        publicKeyPem: SERVER_KEYS.publicKey,
        autoRefresh: false, // Isolate return value & warning check
      });

      const golden: ResolvedTierState = {
        tier: 'PRO_TEAM',
        status: 'ACTIVE',
        licensePath: file.path,
        source: 'jwt',
        isNearExpiry: true,
        daysRemaining: result.daysRemaining,
        capabilities: buildTierCapabilitiesFromPayload(file.payload),
        payload: file.payload,
      };

      expect(result).toEqual(golden);

      // Stderr near-expiry warning text check
      const daysRemaining = Math.ceil((fixedExp * 1000 - Date.now()) / (24 * 60 * 60 * 1000));
      const expectedWarning =
        `[SecureShip] WARNING: Your PRO_TEAM license expires in ${daysRemaining} day(s). ` +
        `Run 'secureship license activate <new-key>' to renew.\n`;
      expect(stderrOutput).toBe(expectedWarning);
      expect(stderrSpy).toHaveBeenCalledTimes(1);
    });

    it('C4: options.publicKeyPem forwards to background refresh verifier; embedded key rejects custom-key refresh', async () => {
      const now = Math.floor(Date.now() / 1000);
      const customKey = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const file = setupLicenseFile(tempDir, { exp: now + 3 * 86400 }, customKey.privateKey);
      const refreshedPayload = createTestPayload({ exp: now + 30 * 86400 });
      const refreshedJwt = signWith(
        customKey.privateKey,
        { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
        refreshedPayload
      );

      // Part 1: With options.publicKeyPem, custom key verification succeeds
      const completionLatch1 = createDeferred<void>();
      const fetchSpy1 = createFetchSpy();
      fetchSpy1.setHandler(
        async () =>
          ({
            ok: true,
            status: 200,
            headers: new Headers({ 'Content-Type': 'application/json' }),
            json: async () => {
              queueMicrotask(() => queueMicrotask(() => completionLatch1.resolve()));
              return { valid: true, refreshedJwt };
            },
          }) as unknown as Response
      );

      await resolveTierCapabilities({
        licensePath: file.path,
        publicKeyPem: customKey.publicKey,
      });
      await completionLatch1.promise;
      expect(fs.readFileSync(file.path, 'utf-8')).toBe(refreshedJwt);

      // Part 2: Without options.publicKeyPem (or env), default key rejects custom-key token
      writeLicenseFile(file.jwt, file.path);
      const fetchSpy2 = createFetchSpy();

      // Token verified with default key will fail signature verification initially in resolveTierCapabilities
      const stateNoKey = await resolveTierCapabilities({
        licensePath: file.path,
      });
      expect(stateNoKey.status).toBe('INVALID_SIGNATURE');
      expect(fetchSpy2.calls.length).toBe(0);
    });

    it('C5: options.licenseServerUrl is forwarded to endpoint', async () => {
      const now = Math.floor(Date.now() / 1000);
      const file = setupLicenseFile(tempDir, { exp: now + 3 * 86400 });
      const fetchSpy = createFetchSpy();

      await resolveTierCapabilities({
        licensePath: file.path,
        publicKeyPem: SERVER_KEYS.publicKey,
        licenseServerUrl: 'https://custom-license-server.corp.internal',
      });

      expect(fetchSpy.calls.length).toBe(1);
      expect(fetchSpy.calls[0]!.url).toBe(
        'https://custom-license-server.corp.internal/v1/validate'
      );
    });
  });

  // ============================================================================
  // LAYER D: Contract tests against REAL LicenseWorker (no hand-written server mock)
  // ============================================================================
  describe('LAYER D: Real Server Worker Contract Tests', () => {
    function setupWorkerEnv(now: number): {
      env: Env;
      mockDb: Map<string, LicenseRecord>;
      serverKeys: { publicKey: string; privateKey: string };
    } {
      const serverKeys = {
        publicKey: SERVER_KEYS.publicKey,
        privateKey: SERVER_KEYS.privateKey,
      };
      const env: Env = {
        JWT_PRIVATE_KEY: serverKeys.privateKey,
        JWT_PUBLIC_KEY: serverKeys.publicKey,
      };
      const mockDb = new Map<string, LicenseRecord>();

      // Seed 3-day near-expiry record
      mockDb.set('SS-PRO-NEAR-EXPIRY', {
        id: 'lic_near_exp_001',
        customer_id: 'cust_renewal',
        activation_code: 'SS-PRO-NEAR-EXPIRY',
        tier: 'PRO_TEAM',
        seats: 5,
        org_id: 'org-enterprise',
        status: 'ACTIVE',
        expires_at: now + 3 * 86400,
        email: 'lead-dev@organization.com',
      });

      return { env, mockDb, serverKeys };
    }

    it('D1: Renewal path: active license expiring in 3 days renewed to +60 days updates local token with greater exp and client verifier passes', async () => {
      const now = Math.floor(Date.now() / 1000);
      const { env, mockDb, serverKeys } = setupWorkerEnv(now);

      // 1. Activate initial token via worker's own /v1/activate
      const activateReq = new Request('https://license.secureship.dev/v1/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          activationCode: 'SS-PRO-NEAR-EXPIRY',
          machineFingerprint: 'machine-node-test-01',
        }),
      });
      const activateRes = await LicenseWorker.handleRequest(activateReq, env, mockDb);
      expect(activateRes.status).toBe(200);
      const activateBody = (await activateRes.json()) as { jwt: string };
      const initialToken = activateBody.jwt;

      // Write initial token to disk
      writeLicenseFile(initialToken, licenseFilePath);
      const initialVerified = verifyLicenseJwt(initialToken, serverKeys.publicKey, now);
      expect(initialVerified.valid).toBe(true);
      const initialExp = initialVerified.payload!.exp;

      // 2. Simulate customer payment renewal: database record expires_at extended to +60 days
      const record = mockDb.get('SS-PRO-NEAR-EXPIRY')!;
      record.expires_at = now + 60 * 86400;

      // 3. Route client's fetch into LicenseWorker.handleRequest
      const fetchSpy = createFetchSpy(async (url, init) => {
        const req = new Request(url, init);
        return LicenseWorker.handleRequest(req, env, mockDb);
      });

      // 4. Run background refresh
      await refreshLicenseInBackground(
        licenseFilePath,
        initialToken,
        'https://license.secureship.dev',
        {
          publicKeyPem: serverKeys.publicKey,
          now,
        }
      );

      expect(fetchSpy.calls.length).toBe(1);
      const refreshedOnDisk = readLicenseFile(licenseFilePath);
      expect(refreshedOnDisk).not.toBeNull();
      expect(refreshedOnDisk).not.toBe(initialToken);

      // 5. Verify refreshed token with client validator
      const refreshedVerified = verifyLicenseJwt(refreshedOnDisk!, serverKeys.publicKey, now);
      expect(refreshedVerified.valid).toBe(true);
      expect(refreshedVerified.payload?.sub).toBe('lead-dev@organization.com');
      expect(refreshedVerified.payload?.orgId).toBe('org-enterprise');
      // Server computed min(now + 30d, record.expires_at) = now + 30d
      expect(refreshedVerified.payload!.exp).toBe(now + 30 * 86400);
      expect(refreshedVerified.payload!.exp).toBeGreaterThan(initialExp);
    });

    it('D2: No-op path: database record NOT extended -> server returns equal exp -> client does NOT write file', async () => {
      const now = Math.floor(Date.now() / 1000);
      const { env, mockDb, serverKeys } = setupWorkerEnv(now);

      // Activate initial token
      const activateReq = new Request('https://license.secureship.dev/v1/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          activationCode: 'SS-PRO-NEAR-EXPIRY',
          machineFingerprint: 'machine-node-test-02',
        }),
      });
      const activateRes = await LicenseWorker.handleRequest(activateReq, env, mockDb);
      const activateBody = (await activateRes.json()) as { jwt: string };
      const initialToken = activateBody.jwt;
      writeLicenseFile(initialToken, licenseFilePath);

      // Record is NOT extended (record.expires_at remains now + 3 * 86400)
      createFetchSpy(async (url, init) => {
        const req = new Request(url, init);
        return LicenseWorker.handleRequest(req, env, mockDb);
      });

      await refreshLicenseInBackground(
        licenseFilePath,
        initialToken,
        'https://license.secureship.dev',
        {
          publicKeyPem: serverKeys.publicKey,
          now,
        }
      );

      // Local file MUST NOT be modified
      expect(fs.readFileSync(licenseFilePath, 'utf-8')).toBe(initialToken);
    });

    it('D3: Revoked license: database status set to REVOKED -> server returns 403 -> file remains unchanged', async () => {
      const now = Math.floor(Date.now() / 1000);
      const { env, mockDb, serverKeys } = setupWorkerEnv(now);

      // Activate token
      const activateReq = new Request('https://license.secureship.dev/v1/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          activationCode: 'SS-PRO-NEAR-EXPIRY',
          machineFingerprint: 'machine-node-test-03',
        }),
      });
      const activateRes = await LicenseWorker.handleRequest(activateReq, env, mockDb);
      const activateBody = (await activateRes.json()) as { jwt: string };
      const initialToken = activateBody.jwt;
      writeLicenseFile(initialToken, licenseFilePath);

      // Set record to REVOKED
      const record = mockDb.get('SS-PRO-NEAR-EXPIRY')!;
      record.status = 'REVOKED';

      createFetchSpy(async (url, init) => {
        const req = new Request(url, init);
        return LicenseWorker.handleRequest(req, env, mockDb);
      });

      await refreshLicenseInBackground(
        licenseFilePath,
        initialToken,
        'https://license.secureship.dev',
        {
          publicKeyPem: serverKeys.publicKey,
          now,
        }
      );

      // File remains unchanged
      expect(fs.readFileSync(licenseFilePath, 'utf-8')).toBe(initialToken);
    });

    it('D4: Server-issued tokens including lid claim pass client offline verifyLicenseJwt', async () => {
      const now = Math.floor(Date.now() / 1000);
      const { env, mockDb, serverKeys } = setupWorkerEnv(now);

      const activateReq = new Request('https://license.secureship.dev/v1/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          activationCode: 'SS-PRO-NEAR-EXPIRY',
          machineFingerprint: 'machine-node-test-04',
        }),
      });
      const activateRes = await LicenseWorker.handleRequest(activateReq, env, mockDb);
      const activateBody = (await activateRes.json()) as { jwt: string };

      // Assert server token has lid claim in raw JWT payload
      const rawPayload = JSON.parse(
        Buffer.from(activateBody.jwt.split('.')[1]!, 'base64url').toString('utf-8')
      ) as ServerJwtPayload;
      expect(rawPayload.lid).toBe('lic_near_exp_001');

      // Assert token passes client offline verifier
      const verified = verifyLicenseJwt(activateBody.jwt, serverKeys.publicKey, now);
      expect(verified.valid).toBe(true);
      expect(verified.payload?.tier).toBe('PRO_TEAM');
      expect(verified.payload?.sub).toBe('lead-dev@organization.com');
      expect(verified.payload?.orgId).toBe('org-enterprise');
    });

    it('D5: Defect reproduction: BASELINE client request (POST + { sub }) against real worker returns 404 (documenting F-LIC-001 defect)', async () => {
      const now = Math.floor(Date.now() / 1000);
      const { env, mockDb } = setupWorkerEnv(now);

      // Recreate exact baseline client request
      const baselineRequest = new Request('https://license.secureship.dev/v1/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sub: 'lead-dev@organization.com' }),
      });

      const response = await LicenseWorker.handleRequest(baselineRequest, env, mockDb);
      // Real worker expects GET with Authorization Bearer token; POST returns 404
      expect(response.status).toBe(404);
      const body = (await response.json()) as { error: string };
      expect(body.error).toBe('Endpoint not found');
    });
  });

  // ============================================================================
  // LAYER F: Hygiene & TypeScript Type Tests
  // ============================================================================
  describe('LAYER F: Hygiene & Type Tests', () => {
    it('F3: No real network calls occur and global fetch is restored cleanly', () => {
      // Verifies globalThis.fetch is restored in afterEach
      expect(typeof globalThis.fetch).toBe('function');
    });

    it('F4: TypeScript compile-time check: 3-argument signature compiles and 4th options is optional', () => {
      type RefreshSignature = (
        licensePath: string,
        currentJwt: string,
        serverUrl?: string,
        options?: { publicKeyPem?: string; timeoutMs?: number; now?: number }
      ) => Promise<void>;

      const typeCheck: RefreshSignature = refreshLicenseInBackground;
      expect(typeof typeCheck).toBe('function');
    });
  });
});
