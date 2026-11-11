import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  LicenseWorker,
  verifyJwtWebCrypto,
  getMockActivations,
  type Env,
  type D1Database,
  type D1PreparedStatement,
} from '../src/worker.js';
import { SERVER_KEYS, createMockDb, activateHelper, signWith } from './fixtures.js';

describe('LAYER C: Revocation, Expiry and Refresh Semantics', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  const nowEpoch = Math.floor(Date.now() / 1000);
  const env: Env = {
    JWT_PRIVATE_KEY: SERVER_KEYS.privateKey,
    JWT_PUBLIC_KEY: SERVER_KEYS.publicKey,
  };

  // C1: Flip DB record to REVOKED gives 403 LICENSE_REVOKED; EXPIRED gives 403 LICENSE_EXPIRED
  it('C1.1: validate returns 403 LICENSE_REVOKED with no refreshedJwt when status is flipped to REVOKED', async () => {
    const mockDb = createMockDb(nowEpoch);
    const { jwt } = await activateHelper(env, mockDb, 'SS-PRO-ACTIVE-0001', 'mach-c1-rev');
    expect(typeof jwt).toBe('string');

    // Flip DB status to REVOKED
    const record = mockDb.get('SS-PRO-ACTIVE-0001')!;
    record.status = 'REVOKED';

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${jwt}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'License is revoked',
      code: 'LICENSE_REVOKED',
    });
    expect(body['refreshedJwt']).toBeUndefined();
  });

  it('C1.2: validate returns 403 LICENSE_EXPIRED with no refreshedJwt when status is flipped to EXPIRED', async () => {
    const mockDb = createMockDb(nowEpoch);
    const { jwt } = await activateHelper(env, mockDb, 'SS-PRO-ACTIVE-0001', 'mach-c1-exp');
    expect(typeof jwt).toBe('string');

    // Flip DB status to EXPIRED
    const record = mockDb.get('SS-PRO-ACTIVE-0001')!;
    record.status = 'EXPIRED';

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${jwt}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'License is expired',
      code: 'LICENSE_EXPIRED',
    });
    expect(body['refreshedJwt']).toBeUndefined();
  });

  // C2: Expiry in past -> 410, Row deleted -> 404, Store throws -> 500
  it('C2.1: validate returns 410 when DB record expires_at is in the past while token is unexpired', async () => {
    const mockDb = createMockDb(nowEpoch);
    // Token is valid until nowEpoch + 86400
    const token = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      {
        lid: 'lic_expired_time',
        sub: 'time@expired.com',
        tier: 'PRO_TEAM',
        seats: 2,
        orgId: 'time-corp',
        iat: nowEpoch - 7200,
        exp: nowEpoch + 86400, // JWT valid
        maxMonthlyAiFixes: 100,
        allowCallPathReachability: true,
        allowCiCdGatekeeper: true,
        allowSignedComplianceExport: true,
        allowAirGappedOnPrem: false,
        featureFlags: {},
      }
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(410);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'License expired',
    });
  });

  it('C2.2: validate returns 404 when license record is deleted from store', async () => {
    const mockDb = createMockDb(nowEpoch);
    const token = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      {
        lid: 'lic_deleted_from_store',
        sub: 'ghost@corp.com',
        tier: 'PRO_TEAM',
        seats: 2,
        orgId: 'ghost-org',
        iat: nowEpoch,
        exp: nowEpoch + 86400,
        maxMonthlyAiFixes: 100,
        allowCallPathReachability: true,
        allowCiCdGatekeeper: true,
        allowSignedComplianceExport: true,
        allowAirGappedOnPrem: false,
        featureFlags: {},
      }
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(404);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'License not found',
    });
  });

  it('C2.3: validate returns 500 LICENSE_STORE_UNAVAILABLE without internal errors when store throws', async () => {
    const failingDb: D1Database = {
      prepare(_query: string): D1PreparedStatement {
        return {
          bind() {
            return this;
          },
          async first<T>(): Promise<T | null> {
            throw new Error('D1_INTERNAL_CORRUPTION: SQLite header corrupted');
          },
          async run() {
            throw new Error('D1_INTERNAL_CORRUPTION');
          },
        };
      },
    };

    const token = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      {
        lid: 'lic_pro_active',
        sub: 'pro@acme.com',
        tier: 'PRO_TEAM',
        seats: 2,
        orgId: 'acme-corp',
        iat: nowEpoch,
        exp: nowEpoch + 86400,
        maxMonthlyAiFixes: 100,
        allowCallPathReachability: true,
        allowCiCdGatekeeper: true,
        allowSignedComplianceExport: true,
        allowAirGappedOnPrem: false,
        featureFlags: {},
      }
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    const res = await LicenseWorker.handleRequest(req, { ...env, DB: failingDb }, undefined);

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'LICENSE_STORE_UNAVAILABLE',
    });
    expect(body['stack']).toBeUndefined();
    expect(body['details']).toBeUndefined();
  });

  // C3: Refresh when <7d remain: exp equals min(now+30d, record.expires_at) exactly
  it('C3.1: caps refreshed token exp at record.expires_at when 3 days remain (< 7 days)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(nowEpoch * 1000));

    const mockDb = createMockDb(nowEpoch);
    const licExpiry = nowEpoch + 3 * 86400; // 3 days remaining

    // Token has 2 days remaining (< 7 days)
    const tokenExp = nowEpoch + 2 * 86400;
    const token = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      {
        lid: 'lic_refresh_3d',
        sub: 'billing@refresh.com',
        tier: 'ENTERPRISE',
        seats: 10,
        orgId: 'refresh-org',
        iat: nowEpoch - 28 * 86400,
        exp: tokenExp,
        maxMonthlyAiFixes: null,
        allowCallPathReachability: true,
        allowCiCdGatekeeper: true,
        allowSignedComplianceExport: true,
        allowAirGappedOnPrem: true,
        featureFlags: {},
      }
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body['valid']).toBe(true);
    expect(typeof body['refreshedJwt']).toBe('string');

    // Verify refreshed token
    const verified = await verifyJwtWebCrypto(
      body['refreshedJwt'] as string,
      SERVER_KEYS.publicKey,
      {
        now: nowEpoch,
      }
    );
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      // Must equal licExpiry, NEVER beyond
      expect(verified.payload.exp).toBe(licExpiry);
      expect(verified.payload.lid).toBe('lic_refresh_3d');
    }
  });

  it('C3.2: sets refreshed token exp to now+30d when license has far-future expiry (365 days)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(nowEpoch * 1000));

    const mockDb = createMockDb(nowEpoch);
    // Token has 5 days remaining (< 7 days)
    const tokenExp = nowEpoch + 5 * 86400;
    const token = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      {
        lid: 'lic_far_future',
        sub: 'billing@mega.com',
        tier: 'ENTERPRISE',
        seats: 50,
        orgId: 'mega-org',
        iat: nowEpoch - 25 * 86400,
        exp: tokenExp,
        maxMonthlyAiFixes: null,
        allowCallPathReachability: true,
        allowCiCdGatekeeper: true,
        allowSignedComplianceExport: true,
        allowAirGappedOnPrem: true,
        featureFlags: {},
      }
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body['valid']).toBe(true);
    expect(typeof body['refreshedJwt']).toBe('string');

    const verified = await verifyJwtWebCrypto(
      body['refreshedJwt'] as string,
      SERVER_KEYS.publicKey,
      {
        now: nowEpoch,
      }
    );
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      // Exactly now + 30 days
      expect(verified.payload.exp).toBe(nowEpoch + 30 * 86400);
      expect(verified.payload.lid).toBe('lic_far_future');
    }
  });

  // C4: Claims come from the DB, not the token
  it('C4: refreshed token carries updated DB tier and capabilities, keeping original lid', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(nowEpoch * 1000));

    const mockDb = createMockDb(nowEpoch);
    // Activate as PRO_TEAM
    const { jwt } = await activateHelper(env, mockDb, 'SS-PRO-ACTIVE-0001', 'mach-c4-upgrade');
    expect(typeof jwt).toBe('string');

    // Upgrade customer in database to ENTERPRISE with 50 seats
    const lic = mockDb.get('SS-PRO-ACTIVE-0001')!;
    lic.tier = 'ENTERPRISE';
    lic.seats = 50;

    // Simulate token near expiry (1 day left)
    const tokenNearExpiry = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      {
        lid: lic.id,
        sub: 'pro@acme.com',
        tier: 'PRO_TEAM', // Old tier in token
        seats: 2, // Old seats in token
        orgId: 'acme-corp',
        iat: nowEpoch - 29 * 86400,
        exp: nowEpoch + 86400, // 1 day left (< 7 days)
        maxMonthlyAiFixes: 100,
        allowCallPathReachability: true,
        allowCiCdGatekeeper: true,
        allowSignedComplianceExport: true,
        allowAirGappedOnPrem: false,
        featureFlags: {},
      }
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${tokenNearExpiry}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body['tier']).toBe('ENTERPRISE');
    expect(typeof body['refreshedJwt']).toBe('string');

    const verified = await verifyJwtWebCrypto(
      body['refreshedJwt'] as string,
      SERVER_KEYS.publicKey,
      {
        now: nowEpoch,
      }
    );
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.payload.tier).toBe('ENTERPRISE');
      expect(verified.payload.seats).toBe(50);
      expect(verified.payload.lid).toBe('lic_pro_active');
      expect(verified.payload.allowAirGappedOnPrem).toBe(true);
      expect(verified.payload.maxMonthlyAiFixes).toBeNull();
    }
  });

  // C5: Token with >7d remaining gives valid:true and no refreshedJwt. Exact body keys.
  it('C5: token with >7d remaining gives valid:true with exact body keys [expiresAt, tier, valid]', async () => {
    const mockDb = createMockDb(nowEpoch);
    // Token has 20 days remaining (> 7 days)
    const token = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      {
        lid: 'lic_pro_active',
        sub: 'pro@acme.com',
        tier: 'PRO_TEAM',
        seats: 2,
        orgId: 'acme-corp',
        iat: nowEpoch - 10 * 86400,
        exp: nowEpoch + 20 * 86400,
        maxMonthlyAiFixes: 100,
        allowCallPathReachability: true,
        allowCiCdGatekeeper: true,
        allowSignedComplianceExport: true,
        allowAirGappedOnPrem: false,
        featureFlags: {},
      }
    );

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body['valid']).toBe(true);
    expect(body['tier']).toBe('PRO_TEAM');
    expect(body['refreshedJwt']).toBeUndefined();

    // Golden assertion: exactly the 3 allowed keys
    const bodyKeys = Object.keys(body).sort();
    expect(bodyKeys).toEqual(['expiresAt', 'tier', 'valid']);
  });

  // C6: last_validated_at is updated on validate
  it('C6: last_validated_at is updated on validate', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(nowEpoch * 1000));

    const mockDb = createMockDb(nowEpoch);
    const { jwt } = await activateHelper(env, mockDb, 'SS-PRO-ACTIVE-0001', 'mach-c6-touch');
    expect(typeof jwt).toBe('string');

    const activationsBefore = getMockActivations(mockDb);
    const initialTouch = activationsBefore.find((a) => a.machine_fingerprint === 'mach-c6-touch')!;
    expect(initialTouch.last_validated_at).toBe(nowEpoch);

    // Fast-forward time to nowEpoch + 1500s
    const futureTime = nowEpoch + 1500;
    vi.setSystemTime(new Date(futureTime * 1000));

    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${jwt}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);
    expect(res.status).toBe(200);

    const activationsAfter = getMockActivations(mockDb);
    const updatedTouch = activationsAfter.find((a) => a.machine_fingerprint === 'mach-c6-touch')!;
    expect(updatedTouch.last_validated_at).toBe(futureTime);
  });
});
