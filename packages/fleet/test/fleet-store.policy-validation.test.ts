import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { FleetStore, FleetStoreValidationError } from '../src/storage/fleet-store.js';
import { FleetServer } from '../src/server/fleet-server.js';
import { makeCanary, makePayload } from './fixtures/store-fixtures.js';
import type { Severity, FleetPolicy } from '@secureship/contracts';

describe('LAYER H: Policy Validation and HTTP Server Mapping (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;
  let primaryDb: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-policy-test-'));
    primaryDb = path.join(tempDir, 'fleet-db.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // H1: updatePolicy table
  describe('H1: updatePolicy validation table and prototype safety', () => {
    it('applies and persists each valid partial update', () => {
      const store = new FleetStore({ storageFile: primaryDb });

      // Valid failOnSeverity
      store.updatePolicy({ failOnSeverity: 'CRITICAL' });
      expect(store.getPolicy().failOnSeverity).toBe('CRITICAL');

      // Valid blockUnreachableSca
      store.updatePolicy({ blockUnreachableSca: true });
      expect(store.getPolicy().blockUnreachableSca).toBe(true);

      // Valid deniedLicenses
      store.updatePolicy({ deniedLicenses: ['MIT', 'Apache-2.0'] });
      expect(store.getPolicy().deniedLicenses).toEqual(['MIT', 'Apache-2.0']);

      // Valid requireHmacAudit
      store.updatePolicy({ requireHmacAudit: false });
      expect(store.getPolicy().requireHmacAudit).toBe(false);

      // Valid policyVersion
      store.updatePolicy({ policyVersion: '2.5' });
      expect(store.getPolicy().policyVersion).toBe('2.5');

      // Verify on-disk persistence
      const reloaded = new FleetStore({ storageFile: primaryDb });
      expect(reloaded.getPolicy().failOnSeverity).toBe('CRITICAL');
      expect(reloaded.getPolicy().blockUnreachableSca).toBe(true);
      expect(reloaded.getPolicy().deniedLicenses).toEqual(['MIT', 'Apache-2.0']);
      expect(reloaded.getPolicy().requireHmacAudit).toBe(false);
      expect(reloaded.getPolicy().policyVersion).toBe('2.5');
    });

    it('drops unknown keys, prototype keys, and nested objects without polluting prototype', () => {
      const store = new FleetStore({ storageFile: primaryDb });
      const initialKeyCount = Object.keys(Object.prototype).length;

      const payload = {
        failOnSeverity: 'MEDIUM' as const,
        evilKey: 'injected-evil-value',
        nestedObject: { subKey: 'value' },
        __proto__: { pollutedField: 'malicious' },
        constructor: { prototype: { ctorPolluted: 'malicious' } },
      };

      store.updatePolicy(payload as unknown as Partial<FleetPolicy>);

      // Prototype remains unpolluted
      expect(({} as Record<string, unknown>).pollutedField).toBeUndefined();
      expect(({} as Record<string, unknown>).ctorPolluted).toBeUndefined();
      expect(Object.keys(Object.prototype).length).toBe(initialKeyCount);

      // Dropped from in-memory policy
      const memPolicy = store.getPolicy() as Record<string, unknown>;
      expect(memPolicy.evilKey).toBeUndefined();
      expect(memPolicy.nestedObject).toBeUndefined();
      expect(memPolicy.failOnSeverity).toBe('MEDIUM');

      // Dropped from on-disk JSON
      const diskContent = fs.readFileSync(primaryDb, 'utf8');
      expect(diskContent.includes('evilKey')).toBe(false);
      expect(diskContent.includes('nestedObject')).toBe(false);
    });

    it('throws FleetStoreValidationError with field names and expected types, never values, leaving memory and disk unchanged', () => {
      const store = new FleetStore({ storageFile: primaryDb });
      store.updatePolicy({ failOnSeverity: 'HIGH' });
      const primaryBytesBefore = fs.readFileSync(primaryDb);
      const canary = makeCanary();

      const invalidCases: Array<{ update: Record<string, unknown>; field: string }> = [
        { update: { failOnSeverity: `invalid-${canary}` }, field: 'failOnSeverity' },
        { update: { failOnSeverity: 5 }, field: 'failOnSeverity' },
        { update: { failOnSeverity: null }, field: 'failOnSeverity' },
        { update: { requireHmacAudit: `no-${canary}` }, field: 'requireHmacAudit' },
        { update: { requireHmacAudit: 1 }, field: 'requireHmacAudit' },
        { update: { blockUnreachableSca: 'true' }, field: 'blockUnreachableSca' },
        { update: { deniedLicenses: `GPL-${canary}` }, field: 'deniedLicenses' },
        { update: { deniedLicenses: [1, 2] }, field: 'deniedLicenses' },
        { update: { deniedLicenses: null }, field: 'deniedLicenses' },
        { update: { policyVersion: 1 }, field: 'policyVersion' },
      ];

      for (const tc of invalidCases) {
        let caught: FleetStoreValidationError | null = null;
        try {
          store.updatePolicy(tc.update as unknown as Partial<FleetPolicy>);
        } catch (err: unknown) {
          if (err instanceof FleetStoreValidationError) {
            caught = err;
          }
        }

        expect(caught).toBeInstanceOf(FleetStoreValidationError);
        expect(caught?.details.length).toBeGreaterThan(0);

        // Details describe field and expected type
        const hasExpectedField = caught?.details.some(
          (d) => d.includes(tc.field) && d.includes('expected')
        );
        expect(hasExpectedField).toBe(true);

        // Details NEVER leak the canary value
        expect(JSON.stringify(caught?.details).includes(canary)).toBe(false);

        // Memory and disk state unchanged
        expect(store.getPolicy().failOnSeverity).toBe('HIGH');
        const primaryBytesAfter = fs.readFileSync(primaryDb);
        expect(Buffer.compare(primaryBytesBefore, primaryBytesAfter)).toBe(0);
      }
    });
  });

  // H2: HTTP API Mapping
  describe('H2: FleetServer HTTP policy endpoint mapping', () => {
    let server: FleetServer;
    let serverPort: number;
    const testToken = 'secure-fleet-test-token-256bit-ok';

    beforeEach(async () => {
      const store = new FleetStore({ storageFile: primaryDb });
      store.ingest(makePayload('repo-init'));

      server = new FleetServer({
        port: 0,
        host: '127.0.0.1',
        authToken: testToken,
        store,
      });
      serverPort = await server.start();
    });

    afterEach(async () => {
      await server.stop();
    });

    function makeRequest(
      method: string,
      reqPath: string,
      body?: string,
      headers: Record<string, string> = {}
    ): Promise<{ status: number; body: string; json: Record<string, unknown> }> {
      return new Promise((resolve, reject) => {
        const req = http.request(
          {
            hostname: '127.0.0.1',
            port: serverPort,
            path: reqPath,
            method,
            headers: {
              ...(body !== undefined ? { 'Content-Length': Buffer.byteLength(body) } : {}),
              ...headers,
            },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (d) => chunks.push(d));
            res.on('end', () => {
              const resBody = Buffer.concat(chunks).toString('utf8');
              let json: Record<string, unknown> = {};
              try {
                json = JSON.parse(resBody);
              } catch {}
              resolve({ status: res.statusCode ?? 0, body: resBody, json });
            });
          }
        );
        req.on('error', reject);
        if (body !== undefined) req.write(body);
        req.end();
      });
    }

    it('POST /api/policy with valid body returns 200 and updated policy', async () => {
      const res = await makeRequest(
        'POST',
        '/api/policy',
        JSON.stringify({ failOnSeverity: 'CRITICAL', blockUnreachableSca: true }),
        {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${testToken}`,
        }
      );

      expect(res.status).toBe(200);
      expect(res.json.failOnSeverity).toBe('CRITICAL');
      expect(res.json.blockUnreachableSca).toBe(true);
    });

    it('POST /api/policy with invalid body returns 400 with exact error structure and leaves disk untouched', async () => {
      const initialDiskBytes = fs.readFileSync(primaryDb);

      const res = await makeRequest(
        'POST',
        '/api/policy',
        JSON.stringify({ failOnSeverity: 'NOT_A_SEVERITY', deniedLicenses: 12345 }),
        {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${testToken}`,
        }
      );

      expect(res.status).toBe(400);
      expect(res.json.error).toBe('Invalid policy payload');
      expect(Array.isArray(res.json.details)).toBe(true);
      expect((res.json.details as string[]).length).toBe(2);

      // On-disk bytes identical
      const diskBytesAfter = fs.readFileSync(primaryDb);
      expect(Buffer.compare(initialDiskBytes, diskBytesAfter)).toBe(0);
    });

    it('POST /api/policy unauthenticated invalid body returns 401 (auth check precedes validation)', async () => {
      const res = await makeRequest(
        'POST',
        '/api/policy',
        JSON.stringify({ failOnSeverity: 'NOT_A_SEVERITY' }),
        {
          'Content-Type': 'application/json',
          // No auth header
        }
      );

      expect(res.status).toBe(401);
      expect(res.json.error).toContain('Unauthorized');
    });

    it('POST /api/policy with wrong Content-Type returns 415', async () => {
      const res = await makeRequest('POST', '/api/policy', 'failOnSeverity=CRITICAL', {
        'Content-Type': 'text/plain',
        Authorization: `Bearer ${testToken}`,
      });

      expect(res.status).toBe(415);
      expect(res.json.error).toBe('Content-Type must be application/json');
    });
  });

  // H3: Property-based consistency over 300 random updates
  describe('H3: Property test over 300 seeded random valid updates', () => {
    it('always validates and persists cleanly across 300 sequential updates with restarts', () => {
      const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
      let seed = 42891;
      function nextRand(): number {
        seed = (seed * 1664525 + 1013904223) % 4294967296;
        return seed / 4294967296;
      }

      let currentExpectedPolicy: FleetPolicy = {
        policyVersion: '1.0',
        failOnSeverity: 'HIGH',
        blockUnreachableSca: false,
        deniedLicenses: ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'],
        requireHmacAudit: true,
        updatedAt: '2026-11-04T00:00:00.000Z',
      };

      const store = new FleetStore({ storageFile: primaryDb });

      for (let i = 1; i <= 300; i++) {
        const sevIdx = Math.floor(nextRand() * severities.length);
        const failOnSeverity = severities[sevIdx]!;
        const blockUnreachableSca = nextRand() > 0.5;
        const requireHmacAudit = nextRand() > 0.5;
        const deniedLicenses = [`LIC-${Math.floor(nextRand() * 10)}`];
        const policyVersion = `v${Math.floor(nextRand() * 5)}.${i}`;

        const update = {
          failOnSeverity,
          blockUnreachableSca,
          requireHmacAudit,
          deniedLicenses,
          policyVersion,
        };

        const updated = store.updatePolicy(update);
        currentExpectedPolicy = {
          ...currentExpectedPolicy,
          ...update,
          updatedAt: updated.updatedAt,
        };

        // Deep-equal check in memory
        expect(store.getPolicy()).toEqual(currentExpectedPolicy);

        // Every 30 iterations, restart store and verify on-disk consistency
        if (i % 30 === 0) {
          const reloaded = new FleetStore({ storageFile: primaryDb });
          expect(reloaded.getPolicy()).toEqual(currentExpectedPolicy);
        }
      }
    });
  });
});
