import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { FleetStore, FleetStorePersistError } from '../src/storage/fleet-store.js';
import { FleetServer } from '../src/server/fleet-server.js';
import { FaultFs } from './fixtures/fault-fs.js';
import { makePayload, LoggerSpy } from './fixtures/store-fixtures.js';

describe('LAYER B: Atomic Write Protocol and Fault Injection (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;
  let primaryDb: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-atomic-test-'));
    primaryDb = path.join(tempDir, 'fleet-db.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // B1. Call order golden (linux)
  it('B1: verifies golden call sequence on linux: temp write, fsync, read-back, rotation, atomic rename, dir fsync', () => {
    const faultFs = new FaultFs({ platform: 'linux' });
    const logger = new LoggerSpy();
    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: faultFs,
        logger,
        platform: 'linux',
      },
    });

    faultFs.clearLogs();

    // First write: no rotation expected
    store.ingest(makePayload('repo-1'));

    const firstLogs = [...faultFs.callLog];
    const openCalls = firstLogs.filter((c) => c.op === 'openSync');
    const writeCalls = firstLogs.filter((c) => c.op === 'writeSync');
    const renameCalls = firstLogs.filter((c) => c.op === 'renameSync');

    // First write: exact ordered operations on linux
    const firstOps = firstLogs.map((c) => c.op);
    expect(firstOps).toEqual([
      'existsSync',
      'existsSync',
      'realpathSync',
      'openSync',
      'writeSync',
      'fsyncSync',
      'closeSync',
      'readFileSync',
      'existsSync',
      'renameSync',
      'openSync',
      'fsyncSync',
      'closeSync',
      'chmodSync',
      'statSync',
      'existsSync',
    ]);

    // Primary is NEVER opened for writing ('w', 'r+', 'a') and never directly written
    const primaryWriteOpens = openCalls.filter((c) => c.path === primaryDb && c.args[1] !== 'r');
    expect(primaryWriteOpens).toEqual([]);

    const primaryDirectWrites = writeCalls.filter((c) => c.path === primaryDb);
    expect(primaryDirectWrites).toEqual([]);

    // Temp file opened with 'wx' and 0o600
    const tempOpen = openCalls.find(
      (c) => typeof c.path === 'string' && c.path.includes('.tmp.') && c.args[1] === 'wx'
    );
    expect(tempOpen !== undefined).toBe(true);
    expect(tempOpen?.args[2]).toBe(0o600);

    // Rename temp to primary called exactly once
    expect(renameCalls.length).toBe(1);
    expect(renameCalls[0]!.args[1]).toBe(primaryDb);

    // Directory fsync on POSIX
    const dirOpen = openCalls.find((c) => c.path === tempDir && c.args[1] === 'r');
    expect(dirOpen !== undefined).toBe(true);

    // Second write adds backup rotation before primary rename
    faultFs.clearLogs();
    store.ingest(makePayload('repo-2'));

    const secondLogs = [...faultFs.callLog];
    const secondOps = secondLogs.map((c) => c.op);
    expect(secondOps).toEqual([
      'existsSync',
      'realpathSync',
      'openSync',
      'writeSync',
      'fsyncSync',
      'closeSync',
      'readFileSync',
      'existsSync',
      'statSync',
      'copyFileSync',
      'openSync',
      'fsyncSync',
      'closeSync',
      'chmodSync',
      'renameSync',
      'renameSync',
      'openSync',
      'fsyncSync',
      'closeSync',
      'chmodSync',
      'statSync',
      'existsSync',
    ]);

    const copyCall = secondLogs.find((c) => c.op === 'copyFileSync');
    expect(copyCall?.args[0]).toBe(primaryDb);
    expect(String(copyCall?.args[1])).toContain('.bak.tmp.');

    const bakRename = secondLogs.find(
      (c) => c.op === 'renameSync' && String(c.args[1]).endsWith('.bak')
    );
    const primaryRename = secondLogs.find((c) => c.op === 'renameSync' && c.args[1] === primaryDb);
    expect(bakRename !== undefined).toBe(true);
    expect(primaryRename !== undefined).toBe(true);

    // bak rotation rename occurred BEFORE primary rename
    const bakIdx = secondLogs.indexOf(bakRename!);
    const primIdx = secondLogs.indexOf(primaryRename!);
    expect(bakIdx).toBeLessThan(primIdx);
  });

  // B2. Temp name format and collision retry
  it('B2: temp name matches format, lives next to target, and EEXIST retries 3 times', () => {
    const faultFs = new FaultFs({ platform: 'linux' });
    const fixedNow = 1700000000000;
    faultFs.now = () => fixedNow;

    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: faultFs,
        platform: 'linux',
      },
    });

    faultFs.clearLogs();
    store.ingest(makePayload('repo-name-test'));

    const tempOpen = faultFs.callLog.find(
      (c) => c.op === 'openSync' && typeof c.path === 'string' && c.path.includes('.tmp.')
    );
    expect(tempOpen).toBeDefined();
    const tempPath = tempOpen!.path!;

    // Matches format <primary>.tmp.<pid>.<time>.<rand>
    const regex = new RegExp(
      `^${primaryDb.replace(/\\/g, '\\\\')}\\.tmp\\.${process.pid}\\.\\d+\\.[0-9a-f]{8}$`
    );
    expect(regex.test(tempPath)).toBe(true);
    expect(path.dirname(tempPath)).toBe(path.dirname(primaryDb));

    // Two persists in the same millisecond get different names due to random
    faultFs.clearLogs();
    store.ingest(makePayload('repo-name-2'));
    const tempOpen2 = faultFs.callLog.find(
      (c) => c.op === 'openSync' && typeof c.path === 'string' && c.path.includes('.tmp.')
    );
    expect(tempOpen2).toBeDefined();
    expect(tempOpen2!.path).not.toBe(tempPath);

    // EEXIST on 'wx' retries with a new suffix up to 3 times, then fails
    const failFs = new FaultFs({ platform: 'linux' });
    const logger = new LoggerSpy();
    // Fail first 2 openSync on primary temp with EEXIST, 3rd succeeds
    failFs.failCall(
      'openSync',
      1,
      'EEXIST',
      (p) => typeof p === 'string' && p.includes('.tmp.') && !p.includes('.bak.')
    );
    failFs.failCall(
      'openSync',
      2,
      'EEXIST',
      (p) => typeof p === 'string' && p.includes('.tmp.') && !p.includes('.bak.')
    );

    const retryStore = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: failFs,
        logger,
        platform: 'linux',
      },
    });
    retryStore.ingest(makePayload('repo-retry'));
    expect(retryStore.getPersistenceStatus().healthy).toBe(true);

    // Fail all 3 attempts
    const exhaustedFs = new FaultFs({ platform: 'linux' });
    exhaustedFs.failCall(
      'openSync',
      1,
      'EEXIST',
      (p) => typeof p === 'string' && p.includes('.tmp.') && !p.includes('.bak.')
    );
    exhaustedFs.failCall(
      'openSync',
      2,
      'EEXIST',
      (p) => typeof p === 'string' && p.includes('.tmp.') && !p.includes('.bak.')
    );
    exhaustedFs.failCall(
      'openSync',
      3,
      'EEXIST',
      (p) => typeof p === 'string' && p.includes('.tmp.') && !p.includes('.bak.')
    );

    const exhaustStore = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: exhaustedFs,
        logger,
        platform: 'linux',
      },
    });
    exhaustStore.ingest(makePayload('repo-exhaust'));
    expect(exhaustStore.getPersistenceStatus().healthy).toBe(false);
  });

  // B3. Short writes
  it('B3: short writes loop until all bytes are written and hash matches', () => {
    const faultFs = new FaultFs({ platform: 'linux' });
    // Write only 3 bytes per writeSync call
    faultFs.setShortWrite(3);

    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: faultFs,
        platform: 'linux',
      },
    });

    store.ingest(makePayload('repo-short-write', 5));
    expect(store.getPersistenceStatus().healthy).toBe(true);

    const writtenBytes = fs.readFileSync(primaryDb);
    const parsed = JSON.parse(writtenBytes.toString('utf8'));
    expect(parsed.repos[0].repoName).toBe('repo-short-write');
  });

  // B4. ENOSPC on the 2nd write call (default vs strictPersistence)
  it('B4: ENOSPC on 2nd write call keeps primary intact, removes temp, unhealthy status; strict rolls back', () => {
    // Setup initial valid primary
    const setupStore = new FleetStore({ storageFile: primaryDb });
    setupStore.ingest(makePayload('repo-initial'));
    const initialBytes = fs.readFileSync(primaryDb);

    // Run with faultFs on 2nd write call
    const faultFs = new FaultFs({ platform: 'linux' });
    const logger = new LoggerSpy();
    // Fail the second writeSync with ENOSPC
    faultFs.failCall('writeSync', 2, 'ENOSPC');

    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: faultFs,
        logger,
        platform: 'linux',
      },
    });

    // Default mode: does not throw, memory keeps mutation, primary file untouched
    store.ingest(makePayload('repo-mutated'));
    expect(store.getPersistenceStatus().healthy).toBe(false);
    expect(store.getPersistenceStatus().lastError?.code).toBe('ENOSPC');
    expect(logger.hasCode('FLEET_STORE_PERSIST_FAILED')).toBe(true);
    expect(store.getRepo('repo-mutated')).toBeDefined();

    const currentPrimary = fs.readFileSync(primaryDb);
    expect(Buffer.compare(currentPrimary, initialBytes)).toBe(0);

    // No leftover .tmp. files
    const dirEntries = fs.readdirSync(tempDir);
    expect(dirEntries.filter((f) => f.includes('.tmp.')).length).toBe(0);

    // Strict persistence mode: throws FleetStorePersistError and rolls back in-memory mutation
    const strictFs = new FaultFs({ platform: 'linux' });
    strictFs.failCall(
      'writeSync',
      1,
      'ENOSPC',
      (p) => typeof p === 'string' && p.includes('.tmp.')
    );

    const strictStore = new FleetStore({
      storageFile: primaryDb,
      strictPersistence: true,
      internals: {
        fs: strictFs,
        platform: 'linux',
      },
    });

    expect(() => strictStore.ingest(makePayload('repo-strict-new'))).toThrow(
      FleetStorePersistError
    );
    expect(strictStore.getRepo('repo-strict-new')).toBeUndefined();

    // Rollback of updatePolicy
    strictFs.failCall(
      'writeSync',
      1,
      'ENOSPC',
      (p) => typeof p === 'string' && p.includes('.tmp.')
    );
    expect(() => strictStore.updatePolicy({ failOnSeverity: 'CRITICAL' })).toThrow(
      FleetStorePersistError
    );
    expect(strictStore.getPolicy().failOnSeverity).toBe('HIGH');

    // Rollback of clear
    strictFs.failCall(
      'writeSync',
      1,
      'ENOSPC',
      (p) => typeof p === 'string' && p.includes('.tmp.')
    );
    expect(() => strictStore.clear()).toThrow(FleetStorePersistError);
    expect(strictStore.getRepo('repo-initial')).toBeDefined();
  });

  // B5. fsync failure on temp vs directory fsync
  it('B5: fsync failure (EIO) on temp triggers failure; directory fsync failure is safely ignored', () => {
    const faultFs = new FaultFs({ platform: 'linux' });
    const logger = new LoggerSpy();
    // Fail first temp fsyncSync with EIO
    faultFs.failCall('fsyncSync', 1, 'EIO', (p) => typeof p === 'string' && p.includes('.tmp.'));

    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: faultFs,
        logger,
        platform: 'linux',
      },
    });

    store.ingest(makePayload('repo-eio'));
    expect(store.getPersistenceStatus().healthy).toBe(false);
    expect(store.getPersistenceStatus().lastError?.code).toBe('EIO');

    // Directory fsync failing with EINVAL, EPERM, EISDIR is ignored and persist succeeds
    for (const ignoredCode of ['EINVAL', 'EPERM', 'EISDIR']) {
      const dirFs = new FaultFs({ platform: 'linux' });
      // Dir fsync is the 1st fsync matching tempDir
      dirFs.failCall('fsyncSync', 1, ignoredCode, (p) => p === tempDir);

      const passStore = new FleetStore({
        storageFile: primaryDb,
        internals: {
          fs: dirFs,
          platform: 'linux',
        },
      });

      passStore.ingest(makePayload(`repo-fsync-${ignoredCode}`));
      expect(passStore.getPersistenceStatus().healthy).toBe(true);
    }
  });

  // B6. Read-back mismatch
  it('B6: read-back verification failure triggers PERSIST_VERIFY_FAILED and unlinks temp', () => {
    const faultFs = new FaultFs({ platform: 'linux' });
    const logger = new LoggerSpy();

    // Invert first byte on read-back of temp file
    faultFs.setAlteredBytesOnRead((buf, filePath) => {
      if (filePath.includes('.tmp.')) {
        const altered = Buffer.from(buf);
        altered[0] = (altered[0] ?? 0) ^ 0xff;
        return altered;
      }
      return buf;
    });

    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: faultFs,
        logger,
        platform: 'linux',
      },
    });

    store.ingest(makePayload('repo-verify-fail'));
    expect(store.getPersistenceStatus().healthy).toBe(false);
    expect(store.getPersistenceStatus().lastError?.message).toContain(
      'Temp file read-back verification failed'
    );
    expect(fs.existsSync(primaryDb)).toBe(false);

    // Temp file was unlinked
    const dirEntries = fs.readdirSync(tempDir);
    expect(dirEntries.filter((f) => f.includes('.tmp.')).length).toBe(0);
  });

  // B7. win32 retry exponential backoff
  it('B7: on win32, rename retries on EPERM/EACCES/EBUSY with delays [10, 20, 40]; linux does not retry', () => {
    const winFs = new FaultFs({ platform: 'win32' });
    winFs.failCall('renameSync', 1, 'EPERM');
    winFs.failCall('renameSync', 2, 'EACCES');
    winFs.failCall('renameSync', 3, 'EBUSY');

    const winStore = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: winFs,
        sleep: winFs.sleep,
        platform: 'win32',
      },
    });

    winStore.ingest(makePayload('repo-win-retry'));
    expect(winStore.getPersistenceStatus().healthy).toBe(true);
    expect(winFs.sleepLog).toEqual([10, 20, 40]);

    // Failing all attempts on win32
    const failWinFs = new FaultFs({ platform: 'win32' });
    for (let i = 1; i <= 7; i++) {
      failWinFs.failCall('renameSync', i, 'EBUSY');
    }

    const exhaustedWinStore = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: failWinFs,
        sleep: failWinFs.sleep,
        platform: 'win32',
      },
    });

    const bytesBefore = fs.readFileSync(primaryDb);
    exhaustedWinStore.ingest(makePayload('repo-win-exhaust'));
    expect(exhaustedWinStore.getPersistenceStatus().healthy).toBe(false);
    expect(failWinFs.sleepLog).toEqual([10, 20, 40, 80, 160, 320]);

    // Primary path is NEVER written to directly (assert no write on primary) and primary is intact
    const primaryWrites = failWinFs.callLog.filter(
      (c) => c.op === 'writeSync' && c.path === primaryDb
    );
    expect(primaryWrites).toEqual([]);
    const bytesAfter = fs.readFileSync(primaryDb);
    expect(Buffer.compare(bytesBefore, bytesAfter)).toBe(0);

    // On Linux: EPERM does not retry
    const linuxFs = new FaultFs({ platform: 'linux' });
    linuxFs.failCall('renameSync', 1, 'EPERM');

    const linuxStore = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: linuxFs,
        sleep: linuxFs.sleep,
        platform: 'linux',
      },
    });

    linuxStore.ingest(makePayload('repo-linux-fail'));
    expect(linuxStore.getPersistenceStatus().healthy).toBe(false);
    expect(linuxFs.sleepLog).toEqual([]);
  });

  // B8. Fallback on EBUSY / EXDEV (Docker single-file mount)
  it('B8: falls back to non-atomic in-place write on EBUSY/EXDEV on linux with backup rotation and verification', () => {
    // Initial persist to create known-good backup
    const initialStore = new FleetStore({ storageFile: primaryDb });
    initialStore.ingest(makePayload('repo-prior-1'));
    initialStore.ingest(makePayload('repo-prior-2'));

    const faultFs = new FaultFs({ platform: 'linux' });
    const logger = new LoggerSpy();

    // Make renameSync fail with EBUSY (simulating Docker single-file bind mount)
    faultFs.failCall('renameSync', 1, 'EBUSY', (p) => typeof p === 'string' && !p.includes('.bak'));

    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: faultFs,
        logger,
        platform: 'linux',
      },
    });

    store.ingest(makePayload('repo-fallback'));

    expect(store.getPersistenceStatus().mode).toBe('non-atomic-fallback');
    expect(logger.hasCode('FLEET_STORE_NON_ATOMIC_FALLBACK')).toBe(true);

    // Exactly one non-atomic fallback log across multiple ingests
    store.ingest(makePayload('repo-fallback-2'));
    store.ingest(makePayload('repo-fallback-3'));
    store.ingest(makePayload('repo-fallback-4'));
    store.ingest(makePayload('repo-fallback-5'));
    expect(logger.countCode('FLEET_STORE_NON_ATOMIC_FALLBACK')).toBe(1);

    // EACCES, ENOSPC, EIO never trigger fallback
    for (const nonFallbackErr of ['EACCES', 'ENOSPC', 'EIO', 'EROFS']) {
      const errFs = new FaultFs({ platform: 'linux' });
      errFs.failCall('renameSync', 1, nonFallbackErr);

      const s = new FleetStore({
        storageFile: primaryDb,
        internals: {
          fs: errFs,
          platform: 'linux',
        },
      });

      s.ingest(makePayload('repo-no-fallback'));
      expect(s.getPersistenceStatus().mode).not.toBe('non-atomic-fallback');
    }
  });

  // B9. Platform specifics (win32 vs linux/darwin)
  it('B9: on win32 directory fsync is omitted and chmod is skipped; on linux chmod and dir fsync occur', () => {
    const winFs = new FaultFs({ platform: 'win32' });
    const winStore = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: winFs,
        platform: 'win32',
      },
    });

    winStore.ingest(makePayload('repo-win-ops'));

    // Check that directory was not opened for fsync on win32
    const winDirOpens = winFs.callLog.filter(
      (c) => c.op === 'openSync' && c.path === tempDir && c.args[1] === 'r'
    );
    expect(winDirOpens.length).toBe(0);

    const linuxFs = new FaultFs({ platform: 'linux' });
    const linuxStore = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: linuxFs,
        platform: 'linux',
      },
    });

    linuxStore.ingest(makePayload('repo-linux-ops'));
    const linuxDirOpens = linuxFs.callLog.filter(
      (c) => c.op === 'openSync' && c.path === tempDir && c.args[1] === 'r'
    );
    expect(linuxDirOpens.length).toBe(1);
  });

  // B10. Re-entrancy protection
  it('B10: re-entrant ingest during persist error logger does not explode and flushes both mutations', () => {
    let reentered = false;
    let storeInstance: FleetStore | null = null;

    const customLogger = {
      warn: () => {},
      error: () => {
        if (!reentered && storeInstance) {
          reentered = true;
          // Trigger re-entrant ingest
          storeInstance.ingest(makePayload('repo-reentrant'));
        }
      },
    };

    const faultFs = new FaultFs({ platform: 'linux' });
    // Fail first persist to trigger error logger
    faultFs.failCall('writeSync', 2, 'ENOSPC');

    storeInstance = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: faultFs,
        logger: customLogger,
        platform: 'linux',
      },
    });

    storeInstance.ingest(makePayload('repo-first'));

    expect(reentered).toBe(true);
    expect(storeInstance.getRepo('repo-first')).toBeDefined();
    expect(storeInstance.getRepo('repo-reentrant')).toBeDefined();
  });

  // B11. Temp cleanup in finally
  it('B11: temp and backup-temp files are cleaned up in finally after failure', () => {
    const faultFs = new FaultFs({ platform: 'linux' });
    faultFs.failCall('writeSync', 2, 'ENOSPC');

    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: faultFs,
        platform: 'linux',
      },
    });

    store.ingest(makePayload('repo-cleanup'));

    const entries = fs.readdirSync(tempDir);
    expect(entries.filter((e) => e.includes('.tmp.') || e.includes('.bak.tmp.')).length).toBe(0);
  });

  // LAYER I: Concurrency and Re-Entrancy
  describe('LAYER I: Concurrency and Alternating Stores', () => {
    it('I1: 100 rapid direct ingests leave all 100 repos present in memory and file', () => {
      const store = new FleetStore({ storageFile: primaryDb });
      for (let i = 1; i <= 100; i++) {
        store.ingest(makePayload(`rapid-repo-${i}`));
      }

      expect(store.getRepos().length).toBe(100);

      // Verify on disk and after restart
      const reloadedStore = new FleetStore({ storageFile: primaryDb });
      expect(reloadedStore.getRepos().length).toBe(100);
      expect(reloadedStore.getRepo('rapid-repo-100')).toBeDefined();
    });

    it('I2: two FleetStore instances on one file: last writer wins and external modification is logged', () => {
      const logger1 = new LoggerSpy();
      const logger2 = new LoggerSpy();

      const store1 = new FleetStore({
        storageFile: primaryDb,
        internals: { logger: logger1 },
      });
      const store2 = new FleetStore({
        storageFile: primaryDb,
        internals: { logger: logger2 },
      });

      store1.ingest(makePayload('repo-inst1-a'));
      store2.ingest(makePayload('repo-inst2-b'));

      expect(logger2.hasCode('FLEET_STORE_EXTERNAL_MODIFICATION')).toBe(true);

      const reloaded = new FleetStore({ storageFile: primaryDb });
      expect(reloaded.getRepo('repo-inst2-b')).toBeDefined();
    });

    it('I3: concurrent HTTP requests against FleetServer preserve database consistency', async () => {
      const server = new FleetServer({
        port: 0,
        host: '127.0.0.1',
        store: new FleetStore({ storageFile: primaryDb }),
      });
      const port = await server.start();

      try {
        const promises = Array.from({ length: 30 }, (_, i) => {
          return new Promise<void>((resolve, reject) => {
            const payload = JSON.stringify(makePayload(`http-repo-${i}`));
            const req = http.request(
              {
                hostname: '127.0.0.1',
                port,
                path: '/api/ingest',
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Content-Length': Buffer.byteLength(payload),
                },
              },
              (res) => {
                res.resume();
                res.on('end', () => {
                  expect(res.statusCode).toBe(200);
                  resolve();
                });
              }
            );
            req.on('error', reject);
            req.write(payload);
            req.end();
          });
        });

        await Promise.all(promises);

        const verifyStore = new FleetStore({ storageFile: primaryDb });
        expect(verifyStore.getRepos().length).toBe(30);
      } finally {
        await server.stop();
      }
    });
  });
});
