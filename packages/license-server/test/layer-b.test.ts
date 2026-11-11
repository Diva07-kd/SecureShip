import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { LicenseWorker, type Env, type ServerJwtPayload } from '../src/worker.js';
import { SERVER_KEYS, ATTACKER_KEYS, signWith, createMockDb, base64UrlEncode } from './fixtures.js';

describe('LAYER B: Oracle Exploit Regression (GET /v1/validate)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const nowEpoch = Math.floor(Date.now() / 1000);
  const env: Env = {
    JWT_PRIVATE_KEY: SERVER_KEYS.privateKey,
    JWT_PUBLIC_KEY: SERVER_KEYS.publicKey,
  };

  // B1: The audit exploit: an UNSIGNED token with tier ENTERPRISE / seats 99999 gives 401
  it('B1: unsigned token with enterprise tier / 99999 seats returns 401 Invalid token without refreshedJwt or claims', async () => {
    const mockDb = createMockDb(nowEpoch);
    const exploitPayload: ServerJwtPayload = {
      lid: 'lic_pro_active',
      sub: 'hacker@pwn.com',
      tier: 'ENTERPRISE',
      seats: 99999,
      orgId: 'forged-enterprise',
      iat: nowEpoch,
      exp: nowEpoch + 86400, // now + 1 day
      maxMonthlyAiFixes: null,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: true,
      featureFlags: {},
    };

    // Forged unsigned token (alg: none, empty signature)
    const exploitToken = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'none', typ: 'JWT' },
      exploitPayload
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${exploitToken}` },
    });

    const res = await LicenseWorker.handleRequest(req, env, mockDb);
    expect(res.status).toBe(401);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'Invalid token',
    });
    expect(body['refreshedJwt']).toBeUndefined();
    expect(body['jwt']).toBeUndefined();
    expect(body['tier']).toBeUndefined();
  });

  // B2: Spy on crypto.subtle.sign. Across ALL rejection cases in A2 to A6 and B1, sign is called 0 times. Control calls it 1 time.
  it('B2: crypto.subtle.sign is called 0 times across all rejection cases and exactly 1 time on control', async () => {
    const mockDb = createMockDb(nowEpoch);
    const signSpy = vi.spyOn(crypto.subtle, 'sign');

    const basePayload = getValidBasePayload(nowEpoch);
    const rejectionTokens = [
      // Tampered payload (signature from basePayload, but payload changed to seats: 99999)
      (() => {
        const validTok = signWith(SERVER_KEYS.privateKey, { alg: 'RS256' }, basePayload);
        const [h, , s] = validTok.split('.');
        const tamperedP = base64UrlEncode(JSON.stringify({ ...basePayload, seats: 99999 }));
        return `${h}.${tamperedP}.${s}`;
      })(),
      // alg none
      signWith(SERVER_KEYS.privateKey, { alg: 'none' }, basePayload),
      // alg HS256
      signWith(SERVER_KEYS.publicKey, { alg: 'HS256' }, basePayload),
      // Attacker signed
      signWith(ATTACKER_KEYS.privateKey, { alg: 'RS256' }, basePayload),
      // Malformed segments
      'a.b.c.d',
      'a..b',
      'a+b.c/d.e',
      // Audit exploit token
      signWith(
        SERVER_KEYS.privateKey,
        { alg: 'none' },
        { ...basePayload, tier: 'ENTERPRISE', seats: 99999 }
      ),
    ];

    for (const badToken of rejectionTokens) {
      const req = new Request('https://license.secureship.dev/v1/validate', {
        method: 'GET',
        headers: { Authorization: `Bearer ${badToken}` },
      });
      await LicenseWorker.handleRequest(req, env, mockDb);
    }

    // Zero invocations across all hostile / invalid tokens
    expect(signSpy).toHaveBeenCalledTimes(0);

    // Control request: valid token with < 7 days remaining (< 7 * 86400s)
    const nearExpiryPayload: ServerJwtPayload = {
      lid: 'lic_pro_active',
      sub: 'pro@acme.com',
      tier: 'PRO_TEAM',
      seats: 2,
      orgId: 'acme-corp',
      iat: nowEpoch - 25 * 86400,
      exp: nowEpoch + 2 * 86400, // 2 days left (< 7 days)
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };
    const validNearExpiryToken = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', kid: 'secureship-2026-01', typ: 'JWT' },
      nearExpiryPayload
    );

    const controlReq = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${validNearExpiryToken}` },
    });
    const controlRes = await LicenseWorker.handleRequest(controlReq, env, mockDb);

    expect(controlRes.status).toBe(200);
    const controlBody = (await controlRes.json()) as Record<string, unknown>;
    expect(controlBody['valid']).toBe(true);
    expect(typeof controlBody['refreshedJwt']).toBe('string');
    // Exactly 1 sign call for the legitimate refresh
    expect(signSpy).toHaveBeenCalledTimes(1);
  });

  // B3: Attacker-signed forged enterprise token returns 401 with no refresh
  it('B3: attacker-signed forged enterprise token returns 401 with no refresh', async () => {
    const mockDb = createMockDb(nowEpoch);
    const forgedPayload: ServerJwtPayload = {
      lid: 'lic_pro_active',
      sub: 'attacker@evil.com',
      tier: 'ENTERPRISE',
      seats: 99999,
      orgId: 'evil-corp',
      iat: nowEpoch,
      exp: nowEpoch + 86400,
      maxMonthlyAiFixes: null,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: true,
      featureFlags: {},
    };

    const forgedToken = signWith(
      ATTACKER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      forgedPayload
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${forgedToken}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(401);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'Invalid token',
    });
    expect(body['refreshedJwt']).toBeUndefined();
  });

  // B4: JWT_PUBLIC_KEY not configured gives 500, and sign is called 0 times
  it('B4: JWT_PUBLIC_KEY not configured returns 500 and sign is called 0 times (fail-closed)', async () => {
    const mockDb = createMockDb(nowEpoch);
    const signSpy = vi.spyOn(crypto.subtle, 'sign');
    const envNoPubKey: Env = {
      JWT_PRIVATE_KEY: SERVER_KEYS.privateKey,
    };

    const token = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      getValidBasePayload(nowEpoch)
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    const res = await LicenseWorker.handleRequest(req, envNoPubKey, mockDb);

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'License server verification key not configured',
    });
    expect(signSpy).toHaveBeenCalledTimes(0);
  });

  // B5: Token missing lid gives 401; errors never echo internal exception messages
  it('B5: token missing lid gives 401 and errors never echo internal exception messages', async () => {
    const mockDb = createMockDb(nowEpoch);
    const noLidPayload = {
      sub: 'dev@secureship.dev',
      tier: 'PRO_TEAM',
      seats: 5,
      orgId: 'acme-corp',
      iat: nowEpoch,
      exp: nowEpoch + 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };

    const tokenWithoutLid = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      noLidPayload
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${tokenWithoutLid}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(401);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'Token does not reference a license; re-activate',
    });
    // Ensure no stack traces or internal exception details leaked
    expect(body['stack']).toBeUndefined();
    expect(body['message']).toBeUndefined();
  });

  // B6: Static guard: in src/worker.ts token payload segment is decoded only inside verifyJwtWebCrypto
  it('B6: static guard verifies token payload is decoded only inside verifyJwtWebCrypto in worker.ts', () => {
    const workerTsPath = path.resolve(__dirname, '../src/worker.ts');
    const workerCode = fs.readFileSync(workerTsPath, 'utf-8');

    // Find occurrences of atob
    const atobMatches = [...workerCode.matchAll(/\batob\s*\(/g)];
    // Expect exactly 3 occurrences: base64UrlDecode, importRsaPrivateKey, getOrImportRsaPublicKey
    expect(atobMatches.length).toBe(3);

    // Assert that in handleRequest (validate handler), there is no atob or payload base64 decoding
    const validateHandlerSection = workerCode.slice(
      workerCode.indexOf("url.pathname === '/v1/validate'"),
      workerCode.indexOf("url.pathname === '/v1/webhook/stripe'")
    );

    expect(validateHandlerSection).not.toContain('atob(');
    expect(validateHandlerSection).not.toContain('Buffer.from(');
    // Payload JSON.parse must not exist in validate handler; it only uses verifyJwtWebCrypto result
    expect(validateHandlerSection).not.toMatch(/JSON\.parse\s*\([^)]*payload/);
  });
});

function getValidBasePayload(now: number): ServerJwtPayload {
  return {
    lid: 'lic_pro_active',
    sub: 'pro@acme.com',
    tier: 'PRO_TEAM',
    seats: 2,
    orgId: 'acme-corp',
    iat: now,
    exp: now + 86400,
    maxMonthlyAiFixes: 100,
    allowCallPathReachability: true,
    allowCiCdGatekeeper: true,
    allowSignedComplianceExport: true,
    allowAirGappedOnPrem: false,
    featureFlags: {},
  };
}
