import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {
  FleetStore,
  FleetStoreValidationError,
  FleetStorePersistError,
  FleetStoreUnsupportedVersionError,
  type FsFacade,
  type FleetStoreLogger,
} from '../src/storage/fleet-store.js';
import { defaultFsFacade } from '../src/storage/atomic-file.js';
import { FleetServer } from '../src/server/fleet-server.js';
import type { FleetIngestPayload } from '@secureship/contracts';

function makePayload(repoName: string): FleetIngestPayload {
  return {
    fleetToken: 'corp-test-token',
    repoName,
    branch: 'main',
    commitSha: 'a1b2c3d4e5f6',
    scannedAt: new Date().toISOString(),
    durationMs: 150,
    summary: {
      totalRaw: 10,
      totalReported: 1,
      totalSuppressed: 9,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { SAST: 0, SCA: 1, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      reachabilitySuppressionPct: 90,
    },
    vulnerabilities: [
      {
        ruleId: 'CVE-2026-1001',
        severity: 'HIGH',
        category: 'SCA',
        reachability: 'REACHABLE_CALL_PATH',
      },
    ],
  };
}

describe('FleetStore Crash-Consistent Persistence & Atomic Protocols (Wave 1 Gate 13)', () => {
  let tempDir: string;
  let primaryFile: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-persistence-test-'));
    primaryFile = path.join(tempDir, 'fleet-db.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // (a) the primary path is never opened for writing in the normal path and rename is called once (spy on the facade)
  it('(a) primary path is never opened for writing in normal path and rename is called once', () => {
    const openedWritePaths: string[] = [];
    const renameCalls: Array<{ oldPath: string; newPath: string }> = [];

    const spiedFacade: FsFacade = {
      ...defaultFsFacade,
      openSync: (p: string, flags: string | number, mode: number | undefined) => {
        const flagStr = String(flags);
        if (flagStr.includes('w') || flagStr.includes('a') || flagStr.includes('+')) {
          openedWritePaths.push(p);
        }
        return defaultFsFacade.openSync(p, flags, mode);
      },
      renameSync: (oldP, newP) => {
        renameCalls.push({ oldPath: oldP, newPath: newP });
        return defaultFsFacade.renameSync(oldP, newP);
      },
    };

    const store = new FleetStore({
      storageFile: primaryFile,
      internals: { fs: spiedFacade },
    });

    const summary = store.ingest(makePayload('repo-atomic'));
    expect(summary.repoName).toBe('repo-atomic');

    // Normal atomic path: primaryFile itself was never opened with write flags
    const normalizedPrimary = path.resolve(primaryFile);
    const directPrimaryWrites = openedWritePaths.filter(
      (p) => path.resolve(p) === normalizedPrimary
    );
    expect(directPrimaryWrites).toHaveLength(0);

    // Exactly one rename was performed targeting the primary destination
    const targetRenames = renameCalls.filter(
      (call) => path.resolve(call.newPath) === normalizedPrimary
    );
    expect(targetRenames).toHaveLength(1);
    expect(targetRenames[0]?.oldPath).toContain('.tmp.');

    // Primary file on disk exists and contains repo data
    expect(fs.existsSync(primaryFile)).toBe(true);
    const rawContent = fs.readFileSync(primaryFile, 'utf8');
    expect(rawContent).toContain('repo-atomic');
  });

  // (b) a truncated primary recovers from the backup with the exact warning code and the primary is healed
  it('(b) truncated primary recovers from backup with exact warning code and primary is healed', () => {
    const warningsLogged: string[] = [];
    const mockLogger: FleetStoreLogger = {
      warn: (code) => {
        warningsLogged.push(code);
      },
      error: () => {},
      debug: () => {},
    };

    // 1. Establish state with 2 ingests so both primary and backup exist
    const storeInit = new FleetStore({ storageFile: primaryFile });
    storeInit.ingest(makePayload('repo-initial-1'));
    storeInit.ingest(makePayload('repo-initial-2'));

    const backupFile = `${primaryFile}.bak`;
    expect(fs.existsSync(primaryFile)).toBe(true);
    expect(fs.existsSync(backupFile)).toBe(true);

    // 2. Corrupt/truncate the primary file
    fs.writeFileSync(primaryFile, '{"formatVersion":1,"repos":[{"repoName":"corrupt-half', 'utf8');

    // 3. Restart FleetStore
    const recoveringStore = new FleetStore({
      storageFile: primaryFile,
      internals: { logger: mockLogger },
    });

    const report = recoveringStore.getLoadReport();
    expect(report.source).toBe('backup');
    expect(report.recovered).toBe(true);
    expect(report.warnings).toContain('FLEET_STORE_RECOVERED_FROM_BACKUP');
    expect(report.warnings).toContain('FLEET_STORE_PRIMARY_CORRUPT');
    expect(warningsLogged).toContain('FLEET_STORE_RECOVERED_FROM_BACKUP');
    expect(warningsLogged).toContain('FLEET_STORE_PRIMARY_CORRUPT');

    // Quarantined file was produced
    expect(report.quarantined.length).toBeGreaterThanOrEqual(1);

    // Repos loaded from backup
    const repos = recoveringStore.getRepos();
    expect(repos.length).toBeGreaterThanOrEqual(1);

    // Primary file is healed on disk: valid JSON containing recovered repos
    const healedRaw = fs.readFileSync(primaryFile, 'utf8');
    const healedJson = JSON.parse(healedRaw) as {
      formatVersion: number;
      repos: Array<{ repoName: string }>;
    };
    expect(healedJson.formatVersion).toBe(1);
    expect(healedJson.repos.length).toBeGreaterThanOrEqual(1);
  });

  // (c) both files corrupt: the empty start is logged (not silent), the originals are quarantined byte-identically, nothing is written at load
  it('(c) both files corrupt: empty start is logged, originals quarantined byte-identically, nothing written at load', () => {
    const errorsLogged: string[] = [];
    const mockLogger: FleetStoreLogger = {
      warn: () => {},
      error: (code) => {
        errorsLogged.push(code);
      },
      debug: () => {},
    };

    const corruptPrimaryPayload = Buffer.from('RAW_CORRUPT_PRIMARY_BYTES_12345');
    const corruptBackupPayload = Buffer.from('RAW_CORRUPT_BACKUP_BYTES_67890');
    const backupFile = `${primaryFile}.bak`;

    fs.writeFileSync(primaryFile, corruptPrimaryPayload);
    fs.writeFileSync(backupFile, corruptBackupPayload);

    const store = new FleetStore({
      storageFile: primaryFile,
      internals: { logger: mockLogger },
    });

    const report = store.getLoadReport();
    expect(report.source).toBe('empty-after-corruption');
    expect(errorsLogged).toContain('FLEET_STORE_STARTED_EMPTY_AFTER_CORRUPTION');

    // Exactly 2 quarantined files created
    expect(report.quarantined).toHaveLength(2);

    // Verify byte-identical preservation of evidence
    const quarantinedPrimaryPath = report.quarantined.find((p) =>
      p.includes('fleet-db.json.corrupt-')
    );
    const quarantinedBackupPath = report.quarantined.find((p) =>
      p.includes('fleet-db.json.bak.corrupt-')
    );

    expect(quarantinedPrimaryPath).toBeDefined();
    expect(quarantinedBackupPath).toBeDefined();

    if (quarantinedPrimaryPath && quarantinedBackupPath) {
      expect(fs.readFileSync(quarantinedPrimaryPath)).toEqual(corruptPrimaryPayload);
      expect(fs.readFileSync(quarantinedBackupPath)).toEqual(corruptBackupPayload);
    }

    // Nothing was written at load time (primaryFile should not exist as a fresh database)
    expect(fs.existsSync(primaryFile)).toBe(false);
    expect(store.getRepos()).toHaveLength(0);
    expect(store.getPolicy().requireHmacAudit).toBe(true);
  });

  // (d) 50 rapid ingests leave 50 repos on disk and after reload
  it('(d) 50 rapid ingests leave 50 repos on disk and after reload', () => {
    const store = new FleetStore({ storageFile: primaryFile });

    for (let i = 0; i < 50; i++) {
      store.ingest(makePayload(`repo-rapid-${i}`));
    }

    expect(store.getRepos()).toHaveLength(50);
    expect(fs.existsSync(primaryFile)).toBe(true);

    const reloaded = new FleetStore({ storageFile: primaryFile });
    expect(reloaded.getRepos()).toHaveLength(50);
    expect(reloaded.getRepo('repo-rapid-0')?.repoName).toBe('repo-rapid-0');
    expect(reloaded.getRepo('repo-rapid-49')?.repoName).toBe('repo-rapid-49');
  });

  // (e) a partial legacy policy keeps requireHmacAudit true
  it('(e) partial legacy policy keeps requireHmacAudit true', () => {
    // Write legacy format file (no formatVersion, no integrity, partial policy)
    const legacyState = {
      repos: [],
      policy: {
        policyVersion: '1.0',
        failOnSeverity: 'CRITICAL',
      },
      updatedAt: new Date().toISOString(),
    };
    fs.writeFileSync(primaryFile, JSON.stringify(legacyState, null, 2), 'utf8');

    const store = new FleetStore({ storageFile: primaryFile });
    const policy = store.getPolicy();

    // Specified field was applied
    expect(policy.failOnSeverity).toBe('CRITICAL');
    // Missing field retained secure default
    expect(policy.requireHmacAudit).toBe(true);
    expect(policy.blockUnreachableSca).toBe(false);
    expect(policy.deniedLicenses).toContain('GPL-3.0');

    expect(store.getLoadReport().source).toBe('primary');
  });

  // (f) updatePolicy validation rejects invalid payload and leaves state and disk unchanged
  it('(f) updatePolicy validates inputs and leaves policy unchanged on failure', () => {
    const store = new FleetStore({ storageFile: primaryFile });
    const initialPolicy = store.getPolicy();

    // Invalid severity
    expect(() => {
      store.updatePolicy({ failOnSeverity: 'INVALID_LEVEL' as unknown as 'CRITICAL' });
    }).toThrow(FleetStoreValidationError);
    expect(store.getPolicy().failOnSeverity).toBe(initialPolicy.failOnSeverity);

    // Invalid types
    expect(() => {
      store.updatePolicy({ requireHmacAudit: 'not-a-boolean' as unknown as boolean });
    }).toThrow(FleetStoreValidationError);
    expect(store.getPolicy().requireHmacAudit).toBe(initialPolicy.requireHmacAudit);
  });

  // (g) strictPersistence rolls back in-memory mutation when disk persistence fails
  it('(g) strictPersistence rolls back in-memory mutation when disk persistence fails', () => {
    let failWrites = false;
    const failingFs: FsFacade = {
      ...defaultFsFacade,
      openSync: (p, flags, mode) => {
        if (failWrites && String(flags).includes('w')) {
          const err = Object.assign(new Error('Disk full'), { code: 'ENOSPC' });
          throw err;
        }
        return defaultFsFacade.openSync(p, flags, mode);
      },
    };

    const store = new FleetStore({
      storageFile: primaryFile,
      strictPersistence: true,
      internals: { fs: failingFs },
    });

    failWrites = true;
    expect(() => {
      store.ingest(makePayload('repo-rollback'));
    }).toThrow(FleetStorePersistError);

    // In-memory state rolled back: repo-rollback was deleted from Map
    expect(store.getRepo('repo-rollback')).toBeUndefined();
    expect(store.getRepos()).toHaveLength(0);
  });

  // (h) FleetServer maps FleetStoreValidationError to HTTP 400 on POST /api/policy
  it('(h) FleetServer returns 400 with details on invalid policy update', async () => {
    const store = new FleetStore({ storageFile: primaryFile });
    const server = new FleetServer({
      port: 0,
      store,
      authToken: 'admin-token',
    });
    const port = await server.start();

    try {
      const res = await new Promise<{ statusCode: number; body: string }>((resolve, reject) => {
        const req = http.request(
          {
            hostname: '127.0.0.1',
            port,
            path: '/api/policy',
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: 'Bearer admin-token',
            },
          },
          (resp) => {
            let data = '';
            resp.on('data', (c) => (data += c));
            resp.on('end', () => resolve({ statusCode: resp.statusCode ?? 0, body: data }));
          }
        );
        req.on('error', reject);
        req.write(JSON.stringify({ failOnSeverity: 'BOGUS_SEVERITY' }));
        req.end();
      });

      expect(res.statusCode).toBe(400);
      const json = JSON.parse(res.body) as { error: string; details: string[] };
      expect(json.error).toBe('Invalid policy payload');
      expect(json.details.length).toBeGreaterThanOrEqual(1);
      expect(json.details[0]).toContain('failOnSeverity');
    } finally {
      await server.stop();
    }
  });

  // (i) FormatVersion > 1 throws FleetStoreUnsupportedVersionError and leaves disk unmodified
  it('(i) database with formatVersion > 1 throws FleetStoreUnsupportedVersionError and leaves disk untouched', () => {
    const v2Content = JSON.stringify({
      formatVersion: 2,
      repos: [],
      policy: { policyVersion: '2.0' },
      futureFeature: 'enabled',
    });
    fs.writeFileSync(primaryFile, v2Content, 'utf8');

    expect(() => {
      new FleetStore({ storageFile: primaryFile });
    }).toThrow(FleetStoreUnsupportedVersionError);

    // Verify disk content was completely untouched
    expect(fs.readFileSync(primaryFile, 'utf8')).toBe(v2Content);
    expect(fs.existsSync(`${primaryFile}.bak`)).toBe(false);
  });

  // (j) Unknown policy keys on disk are stripped on load and not re-persisted
  it('(j) unknown policy keys on disk are stripped on load and not re-persisted', () => {
    const legacyWithUnknown = {
      repos: [],
      policy: {
        policyVersion: '1.0',
        failOnSeverity: 'HIGH',
        maliciousKey: 'attack_vector',
        anotherUnknown: 12345,
      },
    };
    fs.writeFileSync(primaryFile, JSON.stringify(legacyWithUnknown), 'utf8');

    const store = new FleetStore({ storageFile: primaryFile });
    const loadedPolicy = store.getPolicy() as Record<string, unknown>;
    expect(loadedPolicy.maliciousKey).toBeUndefined();
    expect(loadedPolicy.anotherUnknown).toBeUndefined();

    // Trigger persist and verify file on disk does not contain unknown keys
    store.ingest(makePayload('repo-strip-test'));
    const diskContent = fs.readFileSync(primaryFile, 'utf8');
    expect(diskContent).not.toContain('maliciousKey');
    expect(diskContent).not.toContain('anotherUnknown');
  });

  // (k) UTF-8 BOM is stripped on load and parses successfully
  it('(k) UTF-8 BOM is stripped on load and parses cleanly without wiping', () => {
    const state = {
      repos: [
        {
          repoName: 'bom-repo',
          branch: 'main',
          commitSha: 'b01234',
          latestScanAt: new Date().toISOString(),
          riskGrade: 'A',
          riskScore: 92,
          activeCriticals: 0,
          activeHighs: 1,
          reachableCount: 1,
          suppressedCount: 2,
          reachabilitySuppressionPct: 66,
          componentCount: 5,
          compliant: true,
          vulnerabilities: [],
          sbomComponents: [],
        },
      ],
      policy: {
        policyVersion: '1.0',
        failOnSeverity: 'HIGH',
        blockUnreachableSca: false,
        deniedLicenses: ['GPL-3.0'],
        requireHmacAudit: true,
        updatedAt: new Date().toISOString(),
      },
      updatedAt: new Date().toISOString(),
    };

    // Prepend UTF-8 BOM (0xEF, 0xBB, 0xBF)
    const jsonBuf = Buffer.from(JSON.stringify(state), 'utf8');
    const bomBuf = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), jsonBuf]);
    fs.writeFileSync(primaryFile, bomBuf);

    const store = new FleetStore({ storageFile: primaryFile });
    expect(store.getLoadReport().source).toBe('primary');
    expect(store.getRepo('bom-repo')).toBeDefined();
    expect(store.getRepo('bom-repo')?.repoName).toBe('bom-repo');
  });

  // (l) Directory probe failure sets persistence status unhealthy, logs FLEET_STORE_DIR_NOT_WRITABLE, and strictPersistence throws
  it('(l) directory probe failure sets unhealthy status and logs FLEET_STORE_DIR_NOT_WRITABLE', () => {
    const errorsLogged: string[] = [];
    const mockLogger: FleetStoreLogger = {
      warn: () => {},
      error: (code) => {
        errorsLogged.push(code);
      },
      debug: () => {},
    };

    const failingFs: FsFacade = {
      ...defaultFsFacade,
      openSync: (p, flags, mode) => {
        if (p.includes('.probe.')) {
          const err = Object.assign(new Error('Read-only file system'), { code: 'EROFS' });
          throw err;
        }
        return defaultFsFacade.openSync(p, flags, mode);
      },
    };

    // Default mode (strictPersistence: false) starts in-memory
    const store = new FleetStore({
      storageFile: primaryFile,
      internals: { fs: failingFs, logger: mockLogger },
    });

    const status = store.getPersistenceStatus();
    expect(status.healthy).toBe(false);
    expect(errorsLogged).toContain('FLEET_STORE_DIR_NOT_WRITABLE');
    expect(status.lastError?.code).toBe('EROFS');

    // Mutations still work in memory
    const repo = store.ingest(makePayload('memory-repo'));
    expect(repo.repoName).toBe('memory-repo');
    expect(store.getRepo('memory-repo')).toBeDefined();

    // With strictPersistence: true, constructor throws FleetStorePersistError
    expect(() => {
      new FleetStore({
        storageFile: primaryFile,
        strictPersistence: true,
        internals: { fs: failingFs },
      });
    }).toThrow(FleetStorePersistError);
  });

  // (m) Persistence recovery resets consecutiveFailures, logs FLEET_STORE_PERSIST_RECOVERED, and healthy becomes true
  it('(m) persistence recovery resets consecutive failures and logs FLEET_STORE_PERSIST_RECOVERED', () => {
    let failWrites = true;
    const warningsLogged: string[] = [];
    const mockLogger: FleetStoreLogger = {
      warn: (code) => {
        warningsLogged.push(code);
      },
      error: () => {},
      debug: () => {},
    };

    const toggleFs: FsFacade = {
      ...defaultFsFacade,
      openSync: (p, flags, mode) => {
        if (failWrites && String(flags).includes('w') && !p.includes('.probe.')) {
          const err = Object.assign(new Error('Disk I/O error'), { code: 'EIO' });
          throw err;
        }
        return defaultFsFacade.openSync(p, flags, mode);
      },
    };

    const store = new FleetStore({
      storageFile: primaryFile,
      internals: { fs: toggleFs, logger: mockLogger },
    });

    // Ingest while failing
    store.ingest(makePayload('repo-fail'));
    expect(store.getPersistenceStatus().healthy).toBe(false);
    expect(store.getPersistenceStatus().consecutiveFailures).toBe(1);

    // Now disk becomes healthy
    failWrites = false;
    store.ingest(makePayload('repo-recover'));
    expect(store.getPersistenceStatus().healthy).toBe(true);
    expect(store.getPersistenceStatus().consecutiveFailures).toBe(0);
    expect(warningsLogged).toContain('FLEET_STORE_PERSIST_RECOVERED');
  });
});
