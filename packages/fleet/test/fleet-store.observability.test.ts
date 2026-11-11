import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { FleetStore } from '../src/storage/fleet-store.js';
import { FaultFs } from './fixtures/fault-fs.js';
import { makePayload, v1File, LoggerSpy } from './fixtures/store-fixtures.js';

describe('LAYER J: Observability and Logging Discipline (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;
  let primaryDb: string;
  let bakDb: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-obs-test-'));
    primaryDb = path.join(tempDir, 'fleet-db.json');
    bakDb = path.join(tempDir, 'fleet-db.json.bak');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // J1: Status and report shape invariants
  describe('J1: getPersistenceStatus() and getLoadReport() hand-written contracts', () => {
    it('fresh database contract', () => {
      const store = new FleetStore({ storageFile: primaryDb });
      expect(store.getLoadReport()).toEqual({
        source: 'none',
        recovered: false,
        quarantined: [],
        warnings: [],
      });
      expect(store.getPersistenceStatus()).toEqual({
        healthy: true,
        mode: 'atomic',
        consecutiveFailures: 0,
        lastSuccessAt: undefined,
        lastError: undefined,
      });
    });

    it('healthy database after ingest contract', () => {
      const store = new FleetStore({ storageFile: primaryDb });
      store.ingest(makePayload('repo-healthy'));

      const status = store.getPersistenceStatus();
      expect(status.healthy).toBe(true);
      expect(status.mode).toBe('atomic');
      expect(status.consecutiveFailures).toBe(0);
      expect(typeof status.lastSuccessAt).toBe('string');
      expect(status.lastError).toBeUndefined();

      // No customer data in status
      const statusJson = JSON.stringify(status);
      expect(statusJson.includes('repo-healthy')).toBe(false);
    });

    it('ENOSPC failure contract', () => {
      const faultFs = new FaultFs({ platform: 'linux' });
      faultFs.failCall(
        'writeSync',
        1,
        'ENOSPC',
        (p) => typeof p === 'string' && p.includes('.tmp.')
      );

      const store = new FleetStore({
        storageFile: primaryDb,
        internals: { fs: faultFs },
      });

      store.ingest(makePayload('repo-enospc'));

      const status = store.getPersistenceStatus();
      expect(status.healthy).toBe(false);
      expect(status.consecutiveFailures).toBe(1);
      expect(status.lastError?.code).toBe('ENOSPC');
      expect(typeof status.lastError?.at).toBe('string');

      // No customer payload in lastError
      expect(JSON.stringify(status).includes('repo-enospc')).toBe(false);
    });

    it('recovered database contract', () => {
      // Good backup, corrupt primary
      fs.writeFileSync(bakDb, v1File({ repos: [] }), 'utf8');
      fs.writeFileSync(primaryDb, 'corrupt-bytes', 'utf8');

      const store = new FleetStore({ storageFile: primaryDb });
      const report = store.getLoadReport();

      expect(report.source).toBe('backup');
      expect(report.recovered).toBe(true);
      expect(report.quarantined.length).toBe(1);
      expect(report.warnings).toContain('FLEET_STORE_RECOVERED_FROM_BACKUP');
      expect(report.warnings).toContain('FLEET_STORE_PRIMARY_CORRUPT');
    });

    it('memory-only store contract', () => {
      const store = new FleetStore();
      expect(store.getPersistenceStatus()).toEqual({
        healthy: true,
        mode: 'memory-only',
        consecutiveFailures: 0,
      });
    });
  });

  // J2: Rate limiting of persist errors
  describe('J2: Persist error rate limiting and recovery logging', () => {
    it('rate limits consecutive failed persists to at most 1 per minute, allows another after 61s, logs RECOVERED on success', () => {
      let currentTime = 1700000000000;
      const faultFs = new FaultFs({ platform: 'linux' });
      faultFs.now = () => currentTime;
      const logger = new LoggerSpy();

      // Injected fault that fails temp writes
      let failWrites = true;
      faultFs.failAlways(
        'writeSync',
        'ENOSPC',
        (p) => failWrites && typeof p === 'string' && p.includes('.tmp.')
      );

      const store = new FleetStore({
        storageFile: primaryDb,
        internals: {
          fs: faultFs,
          logger,
          now: () => currentTime,
        },
      });

      // Execute 1,000 rapid failed persists within same minute
      for (let i = 1; i <= 1000; i++) {
        // We set failWrites to true so every persist attempt fails
        store.ingest(makePayload(`fail-repo-${i}`));
      }

      // At most 1 FLEET_STORE_PERSIST_FAILED log line within the minute
      expect(logger.countCode('FLEET_STORE_PERSIST_FAILED')).toBe(1);
      expect(store.getPersistenceStatus().consecutiveFailures).toBe(1000);

      // Advance clock by 61 seconds (61000 ms)
      currentTime += 61000;

      // Next failure is allowed to log
      store.ingest(makePayload('fail-after-61s'));
      expect(logger.countCode('FLEET_STORE_PERSIST_FAILED')).toBe(2);

      // Now resolve the fault and perform a successful persist
      failWrites = false;
      faultFs.scriptedFaults.clear();

      store.ingest(makePayload('success-repo'));

      // Emits exactly one FLEET_STORE_PERSIST_RECOVERED log and resets consecutive failures to 0
      expect(logger.countCode('FLEET_STORE_PERSIST_RECOVERED')).toBe(1);
      expect(store.getPersistenceStatus().consecutiveFailures).toBe(0);
      expect(store.getPersistenceStatus().healthy).toBe(true);
    });
  });

  // J3: Default logger stderr vs stdout discipline
  describe('J3: Default logger writes to stderr, never stdout', () => {
    it('default logger writes to console.warn / console.error, never to stdout', () => {
      let stdoutCalled = false;
      let stderrCalled = false;

      const origWarn = console.warn;
      const origError = console.error;

      try {
        console.warn = (..._args) => {
          stderrCalled = true;
        };
        console.error = (..._args) => {
          stderrCalled = true;
        };

        const origStdoutWrite = process.stdout.write;
        process.stdout.write = ((_chunk: unknown) => {
          stdoutCalled = true;
          return true;
        }) as typeof process.stdout.write;

        try {
          // Construct store with failing probe to trigger defaultLogger.error
          const faultFs = new FaultFs({ platform: 'linux' });
          faultFs.failCall(
            'openSync',
            1,
            'EACCES',
            (p) => typeof p === 'string' && p.includes('.probe.')
          );

          new FleetStore({
            storageFile: primaryDb,
            internals: { fs: faultFs },
          });

          expect(stderrCalled).toBe(true);
          expect(stdoutCalled).toBe(false);
        } finally {
          process.stdout.write = origStdoutWrite;
        }
      } finally {
        console.warn = origWarn;
        console.error = origError;
      }
    });
  });
});
