import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  LicenseWorker,
  getMockActivations,
  verifyJwtWebCrypto,
  type Env,
  type LicenseRecord,
  type D1Database,
  type D1PreparedStatement,
} from '../src/worker.js';
import { SERVER_KEYS, createMockDb, createFreshSqliteDb, activateHelper } from './fixtures.js';

interface BackendFixture {
  backendName: 'MockStore' | 'RealSqlStore';
  setup: (nowEpoch: number) => {
    env: Env;
    mockDb?: Map<string, LicenseRecord>;
    getActivationCount: (licenseId: string) => Promise<number>;
    getActivationFingerprints: (licenseId: string) => Promise<string[]>;
  };
}

const backends: BackendFixture[] = [
  {
    backendName: 'MockStore',
    setup: (nowEpoch: number) => {
      const mockDb = createMockDb(nowEpoch);
      const env: Env = {
        JWT_PRIVATE_KEY: SERVER_KEYS.privateKey,
        JWT_PUBLIC_KEY: SERVER_KEYS.publicKey,
      };
      return {
        env,
        mockDb,
        getActivationCount: async (licenseId: string) =>
          getMockActivations(mockDb).filter((a) => a.license_id === licenseId).length,
        getActivationFingerprints: async (licenseId: string) =>
          getMockActivations(mockDb)
            .filter((a) => a.license_id === licenseId)
            .map((a) => a.machine_fingerprint),
      };
    },
  },
  {
    backendName: 'RealSqlStore',
    setup: (nowEpoch: number) => {
      const { db, d1 } = createFreshSqliteDb(nowEpoch);
      const env: Env = {
        DB: d1,
        JWT_PRIVATE_KEY: SERVER_KEYS.privateKey,
        JWT_PUBLIC_KEY: SERVER_KEYS.publicKey,
      };
      return {
        env,
        mockDb: undefined,
        getActivationCount: async (licenseId: string) => {
          const row = db
            .prepare('SELECT COUNT(*) as count FROM activations WHERE license_id = ?')
            .get(licenseId) as { count: number };
          return Number(row.count);
        },
        getActivationFingerprints: async (licenseId: string) => {
          const rows = db
            .prepare('SELECT machine_fingerprint FROM activations WHERE license_id = ?')
            .all(licenseId) as Array<{ machine_fingerprint: string }>;
          return rows.map((r) => r.machine_fingerprint);
        },
      };
    },
  },
];

describe.each(backends)('LAYER D: Seat Enforcement ($backendName)', ({ backendName, setup }) => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const nowEpoch = Math.floor(Date.now() / 1000);

  // D1: 2-seat license: fp1 and fp2 give 200, fp3 gives 403 SEATS_EXCEEDED
  it('D1: strictly enforces 2-seat limit: fp1/fp2 give 200, fp3 gives 403 with exact error body', async () => {
    const { env, mockDb, getActivationCount } = setup(nowEpoch);
    const code = 'SS-PRO-2SEATS-0001';
    const licId = 'lic_2seats';

    // 1. First machine activates -> 200
    const res1 = await activateHelper(env, mockDb, code, 'mach-fp-1');
    expect(res1.status).toBe(200);
    expect(res1.body['success']).toBe(true);
    expect(typeof res1.jwt).toBe('string');
    expect(await getActivationCount(licId)).toBe(1);

    // 2. Second machine activates -> 200
    const res2 = await activateHelper(env, mockDb, code, 'mach-fp-2');
    expect(res2.status).toBe(200);
    expect(res2.body['success']).toBe(true);
    expect(typeof res2.jwt).toBe('string');
    expect(await getActivationCount(licId)).toBe(2);

    // 3. Third machine activates -> 403 SEATS_EXCEEDED
    const res3 = await activateHelper(env, mockDb, code, 'mach-fp-3');
    expect(res3.status).toBe(403);
    expect(res3.body).toEqual({
      error: 'SEATS_EXCEEDED',
      message: 'License seat limit reached',
    });
    expect(res3.jwt).toBeUndefined();
    // Activation count stays strictly 2
    expect(await getActivationCount(licId)).toBe(2);
  });

  // D2: Re-activating fp1 gives 200 and count stays 2. Trimmed variants map to same seat. Case-sensitive identity.
  it('D2: re-activation is idempotent, trimmed variants map to same seat, case-sensitive identity', async () => {
    const { env, mockDb, getActivationCount, getActivationFingerprints } = setup(nowEpoch);
    const code = 'SS-PRO-2SEATS-0001';
    const licId = 'lic_2seats';

    // Activate fp1 and fp2
    await activateHelper(env, mockDb, code, 'mach-fp-1');
    await activateHelper(env, mockDb, code, 'mach-fp-2');
    expect(await getActivationCount(licId)).toBe(2);

    // Re-activate fp1 -> 200, count remains 2
    const resReactivate = await activateHelper(env, mockDb, code, 'mach-fp-1');
    expect(resReactivate.status).toBe(200);
    expect(resReactivate.body['success']).toBe(true);
    expect(await getActivationCount(licId)).toBe(2);

    // Trimmed variant "  mach-fp-1  " maps to same seat
    const resTrimmed = await activateHelper(env, mockDb, code, '  mach-fp-1  ');
    expect(resTrimmed.status).toBe(200);
    expect(await getActivationCount(licId)).toBe(2);

    // Case-sensitivity: uppercase "MACH-FP-1" is a distinct machine fingerprint
    // Because seats are full (2/2), uppercase variant must be rejected as 3rd seat attempt
    const resUpper = await activateHelper(env, mockDb, code, 'MACH-FP-1');
    expect(resUpper.status).toBe(403);
    expect(resUpper.body['error']).toBe('SEATS_EXCEEDED');
    expect(await getActivationCount(licId)).toBe(2);

    const fps = await getActivationFingerprints(licId);
    expect(fps.sort()).toEqual(['mach-fp-1', 'mach-fp-2']);
  });

  // D3: 1-seat license: fp1 OK, fp2 403. POST /v1/deactivate fp1 releases seat, then fp2 200. Idempotent false. Unknown code 404.
  it('D3: 1-seat license lifecycle: deactivate releases seat, idempotent deactivate returns released:false, unknown code 404', async () => {
    const { env, mockDb, getActivationCount } = setup(nowEpoch);
    const code = 'SS-PRO-1SEAT-0001';
    const licId = 'lic_1seat';

    // 1. fp1 succeeds
    const act1 = await activateHelper(env, mockDb, code, 'solo-fp-1');
    expect(act1.status).toBe(200);

    // 2. fp2 rejected (1/1 seats used)
    const act2Fail = await activateHelper(env, mockDb, code, 'solo-fp-2');
    expect(act2Fail.status).toBe(403);
    expect(await getActivationCount(licId)).toBe(1);

    // 3. Deactivate fp1 -> released: true
    const deactReq = new Request('https://license.secureship.dev/v1/deactivate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ activationCode: code, machineFingerprint: 'solo-fp-1' }),
    });
    const deactRes = await LicenseWorker.handleRequest(deactReq, env, mockDb);
    expect(deactRes.status).toBe(200);
    const deactBody = (await deactRes.json()) as Record<string, unknown>;
    expect(deactBody).toEqual({ success: true, released: true });
    expect(await getActivationCount(licId)).toBe(0);

    // 4. fp2 can now activate
    const act2Success = await activateHelper(env, mockDb, code, 'solo-fp-2');
    expect(act2Success.status).toBe(200);
    expect(await getActivationCount(licId)).toBe(1);

    // 5. Deactivating an already-released or unknown machine returns released: false
    const deactAgainReq = new Request('https://license.secureship.dev/v1/deactivate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ activationCode: code, machineFingerprint: 'solo-fp-1' }),
    });
    const deactAgainRes = await LicenseWorker.handleRequest(deactAgainReq, env, mockDb);
    expect(deactAgainRes.status).toBe(200);
    const deactAgainBody = (await deactAgainRes.json()) as Record<string, unknown>;
    expect(deactAgainBody).toEqual({ success: true, released: false });

    // 6. Unknown activation code on deactivate gives 404
    const deactUnknownReq = new Request('https://license.secureship.dev/v1/deactivate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode: 'SS-NONEXISTENT-CODE',
        machineFingerprint: 'solo-fp-2',
      }),
    });
    const deactUnknownRes = await LicenseWorker.handleRequest(deactUnknownReq, env, mockDb);
    expect(deactUnknownRes.status).toBe(404);
  });

  // D4: machineFingerprint missing, empty, whitespace-only, 257 chars: 400 MACHINE_FINGERPRINT_REQUIRED. No row created.
  it('D4: invalid machineFingerprints return 400 MACHINE_FINGERPRINT_REQUIRED without creating rows', async () => {
    const { env, mockDb, getActivationCount } = setup(nowEpoch);
    const code = 'SS-PRO-2SEATS-0001';
    const licId = 'lic_2seats';

    const invalidFps = [
      undefined,
      '',
      '   ',
      '\t\n  ',
      'x'.repeat(257), // 257 characters
    ];

    for (const badFp of invalidFps) {
      const res = await activateHelper(env, mockDb, code, badFp);
      expect(res.status).toBe(400);
      expect(res.body['error']).toBe('MACHINE_FINGERPRINT_REQUIRED');
    }

    expect(await getActivationCount(licId)).toBe(0);
  });

  // D5: Concurrency: Promise.all of 25 activations with distinct fingerprints on 5-seat license gives exactly 5x 200 and 20x 403. Repeated 20 times.
  it('D5: Promise.all of 25 activations on 5-seat license yields exactly 5x 200 and 20x 403 (20 shuffled runs)', async () => {
    // Run 20 iterations with shuffled arrival order
    for (let run = 0; run < 20; run++) {
      const { env, mockDb, getActivationCount } = setup(nowEpoch);
      const code = 'SS-PRO-5SEATS-0001';
      const licId = 'lic_5seats';

      // 25 distinct fingerprints
      const fps = Array.from({ length: 25 }, (_, i) => `fp_conc_${run}_${i}`);
      // Shuffle array
      const shuffledFps = [...fps].sort(() => Math.random() - 0.5);

      const promises = shuffledFps.map((fp) => activateHelper(env, mockDb, code, fp));
      const results = await Promise.all(promises);

      const status200 = results.filter((r) => r.status === 200);
      const status403 = results.filter((r) => r.status === 403);

      expect(status200.length).toBe(5);
      expect(status403.length).toBe(20);
      expect(await getActivationCount(licId)).toBe(5);
    }
  });

  // D6: Concurrent same-fingerprint activation (10 parallel, empty license) gives 10x 200 and exactly 1 row
  it('D6: concurrent same-fingerprint activation (10 parallel) gives 10x 200 and exactly 1 row', async () => {
    const { env, mockDb, getActivationCount } = setup(nowEpoch);
    const code = 'SS-PRO-5SEATS-0001';
    const licId = 'lic_5seats';

    const identicalFp = 'mach-identical-fp-race';
    const promises = Array.from({ length: 10 }, () =>
      activateHelper(env, mockDb, code, identicalFp)
    );
    const results = await Promise.all(promises);

    const status200 = results.filter((r) => r.status === 200);
    expect(status200.length).toBe(10);
    expect(await getActivationCount(licId)).toBe(1);
  });

  // D7: A seat is not burned on failure (missing signing key -> 500 & 0 rows; throwing private key -> 500 & 0 rows)
  it('D7.1: signing key missing returns 500 before consuming seat (0 rows created)', async () => {
    const { env, mockDb, getActivationCount } = setup(nowEpoch);
    const code = 'SS-PRO-2SEATS-0001';
    const licId = 'lic_2seats';

    const envNoSignKey: Env = {
      ...env,
      JWT_PRIVATE_KEY: undefined,
    };

    const res = await activateHelper(envNoSignKey, mockDb, code, 'mach-no-sign-key');
    expect(res.status).toBe(500);
    expect(res.body['error']).toContain('signing key not configured');
    expect(await getActivationCount(licId)).toBe(0);
  });

  it('D7.2: invalid private key causes rollback after seat claim (0 rows remain)', async () => {
    const { env, mockDb, getActivationCount } = setup(nowEpoch);
    const code = 'SS-PRO-2SEATS-0001';
    const licId = 'lic_2seats';

    // Pass garbage private key that fails during signing
    const envBadPrivKey: Env = {
      ...env,
      JWT_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nGARBAGE\n-----END PRIVATE KEY-----',
    };

    const res = await activateHelper(envBadPrivKey, mockDb, code, 'mach-throw-priv-key');
    expect(res.status).toBe(500);
    expect(res.body['error']).toBe('Failed to sign activation token');
    // Seat was released in catch block: exactly 0 rows remain
    expect(await getActivationCount(licId)).toBe(0);
  });

  // D8: If activation write fails (store throws on insert), result is 500 and NO jwt in body
  it('D8: store error during seat insertion returns 500 and no jwt in body', async () => {
    if (backendName === 'MockStore') {
      // For MockStore, simulate store throwing by overriding method
      const failingDb: D1Database = {
        prepare(_query: string): D1PreparedStatement {
          return {
            bind() {
              return this;
            },
            async first<T>(): Promise<T | null> {
              return {
                id: 'lic_2seats',
                customer_id: 'cust_02',
                activation_code: 'SS-PRO-2SEATS-0001',
                tier: 'PRO_TEAM',
                seats: 2,
                org_id: 'duo-org',
                status: 'ACTIVE',
                expires_at: nowEpoch + 86400,
                email: 'duo@team.com',
              } as T;
            },
            async run() {
              throw new Error('D1_IOERR: I/O write failure');
            },
          };
        },
      };

      const res = await activateHelper(
        { DB: failingDb, JWT_PRIVATE_KEY: SERVER_KEYS.privateKey },
        undefined,
        'SS-PRO-2SEATS-0001',
        'mach-store-err'
      );
      expect(res.status).toBe(500);
      expect(res.body['error']).toBe('Failed to record activation');
      expect(res.jwt).toBeUndefined();
    } else {
      // For RealSqlStore, wrap D1 Database to throw on activations INSERT
      const { d1 } = createFreshSqliteDb(nowEpoch);
      const originalPrepare = d1.prepare.bind(d1);
      const throwingD1: D1Database = {
        prepare(query: string) {
          if (query.includes('INSERT INTO activations')) {
            return {
              bind() {
                return this;
              },
              async first<T>(): Promise<T | null> {
                return null;
              },
              async run() {
                throw new Error('D1_CATASTROPHIC_DISK_ERROR');
              },
            };
          }
          return originalPrepare(query);
        },
      };

      const res = await activateHelper(
        { DB: throwingD1, JWT_PRIVATE_KEY: SERVER_KEYS.privateKey },
        undefined,
        'SS-PRO-2SEATS-0001',
        'mach-store-err'
      );
      expect(res.status).toBe(500);
      expect(res.body['error']).toBe('Failed to record activation');
      expect(res.jwt).toBeUndefined();
    }
  });

  // D9: REVOKED/EXPIRED licenses return 403/410 on activate and consume no seat
  it('D9: REVOKED licenses return 403 and EXPIRED licenses return 410 on activate without consuming seats', async () => {
    const { env, mockDb, getActivationCount } = setup(nowEpoch);

    // 1. REVOKED code
    const resRev = await activateHelper(env, mockDb, 'SS-PRO-REVOKED-0001', 'mach-d9-rev');
    expect(resRev.status).toBe(403);
    expect(resRev.body['error']).toContain('revoked');
    expect(await getActivationCount('lic_revoked')).toBe(0);

    // 2. EXPIRED status code
    const resExpStatus = await activateHelper(env, mockDb, 'SS-PRO-EXPIRED-STATUS', 'mach-d9-exp');
    expect(resExpStatus.status).toBe(403);
    expect(resExpStatus.body['error']).toContain('expired');
    expect(await getActivationCount('lic_expired_status')).toBe(0);

    // 3. EXPIRED by timestamp code
    const resExpTime = await activateHelper(env, mockDb, 'SS-PRO-EXPIRED-TIME', 'mach-d9-exptime');
    expect(resExpTime.status).toBe(410);
    expect(resExpTime.body['error']).toContain('expired');
    expect(await getActivationCount('lic_expired_time')).toBe(0);
  });

  // D10: Issued tokens carry lid equal to license id; all other claims unchanged from baseline
  it('D10: issued token carries lid equal to license id and all other claims match golden baseline', async () => {
    const { env, mockDb } = setup(nowEpoch);
    const code = 'SS-PRO-ACTIVE-0001';
    const expectedLicenseId = 'lic_pro_active';

    const res = await activateHelper(env, mockDb, code, 'mach-d10-golden');
    expect(res.status).toBe(200);
    expect(typeof res.jwt).toBe('string');

    const verified = await verifyJwtWebCrypto(res.jwt!, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(verified.ok).toBe(true);

    if (verified.ok) {
      const payload = verified.payload;
      // Assert lid claim
      expect(payload.lid).toBe(expectedLicenseId);

      // Extract non-lid claims and verify deep equality against baseline schema defaults
      const { lid, iat: _iat, exp, ...stableClaims } = payload;
      expect(lid).toBe(expectedLicenseId);

      const goldenBaselineStableClaims = {
        sub: 'pro@acme.com',
        tier: 'PRO_TEAM',
        seats: 2,
        orgId: 'acme-corp',
        maxMonthlyAiFixes: 100,
        allowCallPathReachability: true,
        allowCiCdGatekeeper: true,
        allowSignedComplianceExport: true,
        allowAirGappedOnPrem: false,
        featureFlags: {},
      };

      expect(stableClaims).toEqual(goldenBaselineStableClaims);
      expect(exp).toBe(nowEpoch + 30 * 86400);
    }
  });
});
