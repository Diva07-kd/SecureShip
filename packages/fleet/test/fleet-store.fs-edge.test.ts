import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { FleetStore, FleetStorePersistError } from '../src/storage/fleet-store.js';
import { FaultFs } from './fixtures/fault-fs.js';
import { makePayload, LoggerSpy } from './fixtures/store-fixtures.js';

describe('LAYER F: Filesystem Edge Cases, Symlinks and Storage Modes (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;
  let primaryDb: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fs-edge-test-'));
    primaryDb = path.join(tempDir, 'fleet-db.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // F1: Symlinked primary and symlinked data directory
  describe('F1: Symlinked primary target handling', () => {
    it('updates real target file through symlink, preserving symlink and placing temps next to target', () => {
      const realDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-real-target-'));
      const realTarget = path.join(realDir, 'real-fleet-db.json');
      const symlinkPath = path.join(tempDir, 'symlinked-db.json');

      let canSymlink = false;
      try {
        fs.symlinkSync(realTarget, symlinkPath, 'file');
        canSymlink = true;
      } catch {
        console.log('Symlink creation not permitted on this host (logged skip)');
      }

      if (!canSymlink) {
        expect(process.platform).toBe('win32');
        try {
          fs.rmSync(realDir, { recursive: true, force: true });
        } catch {}
        return;
      }

      try {
        const store = new FleetStore({ storageFile: symlinkPath });
        store.ingest(makePayload('repo-symlink-1'));
        store.ingest(makePayload('repo-symlink-2'));

        // 1. Symlink itself is preserved and is still a symbolic link
        const linkStat = fs.lstatSync(symlinkPath);
        expect(linkStat.isSymbolicLink()).toBe(true);

        // 2. Real target holds the updated content
        expect(fs.existsSync(realTarget)).toBe(true);
        const content = fs.readFileSync(realTarget, 'utf8');
        expect(content.includes('repo-symlink-2')).toBe(true);

        // 3. Backup file was created next to the REAL target, not next to the link
        expect(fs.existsSync(`${realTarget}.bak`)).toBe(true);
        expect(fs.existsSync(`${symlinkPath}.bak`)).toBe(false);

        // 4. Nothing extra created in link dir
        const linkDirFiles = fs.readdirSync(tempDir);
        expect(linkDirFiles.filter((f) => f.includes('.tmp.')).length).toBe(0);
      } finally {
        try {
          fs.rmSync(realDir, { recursive: true, force: true });
        } catch {}
      }
    });
  });

  // F2: Nested directories, relative paths, Unicode and spaces
  describe('F2: Nested directories, relative paths, spaces and Unicode', () => {
    it('creates non-existent nested parent directories and persists cleanly', () => {
      const nestedDb = path.join(tempDir, 'sub1', 'sub2', 'sub3', 'fleet-db.json');
      const store = new FleetStore({ storageFile: nestedDb });
      store.ingest(makePayload('repo-nested'));

      expect(fs.existsSync(nestedDb)).toBe(true);
      const reloaded = new FleetStore({ storageFile: nestedDb });
      expect(reloaded.getRepo('repo-nested')).toBeDefined();
    });

    it('supports paths with spaces and Unicode characters (including NFC comparison)', () => {
      // Name with spaces and Unicode (combining marks)
      const unicodeDirName = 'secureship space 🛡️ 日本語 e\u0301';
      const unicodeDb = path.join(tempDir, unicodeDirName, 'fleet-db.json');

      const store = new FleetStore({ storageFile: unicodeDb });
      store.ingest(makePayload('repo-unicode'));

      expect(fs.existsSync(unicodeDb)).toBe(true);

      const reloaded = new FleetStore({ storageFile: unicodeDb });
      expect(reloaded.getRepo('repo-unicode')).toBeDefined();

      // Read back path NFC normalization comparison
      const normDir = path.dirname(unicodeDb).normalize('NFC');
      expect(normDir.includes('日本語')).toBe(true);
    });

    it('supports relative storage paths', () => {
      const relPath = path.join(tempDir, 'rel-fleet-db.json');
      const relFromCwd = path.relative(process.cwd(), relPath);

      const store = new FleetStore({ storageFile: relFromCwd });
      store.ingest(makePayload('repo-relative'));

      expect(fs.existsSync(relPath)).toBe(true);
      const reloaded = new FleetStore({ storageFile: relFromCwd });
      expect(reloaded.getRepo('repo-relative')).toBeDefined();
    });
  });

  // F3: Read-only directory handling
  describe('F3: Read-only data directory handling', () => {
    it('logs FLEET_STORE_DIR_NOT_WRITABLE, marks unhealthy, in-memory ingest works, no throw in default mode', () => {
      const faultFs = new FaultFs({ platform: 'linux' });
      const logger = new LoggerSpy();
      // Fail directory probe with EROFS
      faultFs.failCall(
        'openSync',
        1,
        'EROFS',
        (p) => typeof p === 'string' && p.includes('.probe.')
      );

      const store = new FleetStore({
        storageFile: primaryDb,
        internals: {
          fs: faultFs,
          logger,
          platform: 'linux',
        },
      });

      // 1. Exactly one FLEET_STORE_DIR_NOT_WRITABLE log
      expect(logger.countCode('FLEET_STORE_DIR_NOT_WRITABLE')).toBe(1);

      // 2. Status unhealthy with lastError set
      const status = store.getPersistenceStatus();
      expect(status.healthy).toBe(false);
      expect(status.lastError?.code).toBe('EROFS');

      // 3. In-memory ingest still works and returns summary without throwing
      const summary = store.ingest(makePayload('repo-mem-only'));
      expect(summary.repoName).toBe('repo-mem-only');
      expect(store.getRepo('repo-mem-only')).toBeDefined();
    });

    it('throws FleetStorePersistError from constructor in strictPersistence mode on probe failure', () => {
      const faultFs = new FaultFs({ platform: 'linux' });
      faultFs.failCall(
        'openSync',
        1,
        'EACCES',
        (p) => typeof p === 'string' && p.includes('.probe.')
      );

      expect(
        () =>
          new FleetStore({
            storageFile: primaryDb,
            strictPersistence: true,
            internals: {
              fs: faultFs,
              platform: 'linux',
            },
          })
      ).toThrow(FleetStorePersistError);

      // No file created
      expect(fs.existsSync(primaryDb)).toBe(false);
    });
  });

  // F4: Storage path is a directory (EISDIR)
  describe('F4: Storage path is a directory', () => {
    it('handles storage path being an existing directory gracefully without crashing process', () => {
      const dirAsDb = path.join(tempDir, 'dir-as-db');
      fs.mkdirSync(dirAsDb, { recursive: true });

      const logger = new LoggerSpy();
      const store = new FleetStore({
        storageFile: dirAsDb,
        internals: { logger },
      });

      // Ingest should fail gracefully without crashing
      store.ingest(makePayload('repo-eisdir'));
      expect(store.getPersistenceStatus().healthy).toBe(false);
      expect(store.getRepo('repo-eisdir')).toBeDefined();
    });
  });

  // F5: Memory-only store (no storageFile)
  describe('F5: Memory-only store behavior', () => {
    it('executes zero filesystem calls and zero logs with mode "memory-only"', () => {
      const faultFs = new FaultFs({ platform: 'linux' });
      const logger = new LoggerSpy();

      const store = new FleetStore({
        internals: {
          fs: faultFs,
          logger,
        },
      });

      // No fs calls during construction
      expect(faultFs.callLog.length).toBe(0);
      expect(logger.entries.length).toBe(0);

      // Persistence status
      expect(store.getPersistenceStatus()).toEqual({
        healthy: true,
        mode: 'memory-only',
        consecutiveFailures: 0,
      });

      // Ingest runs entirely in memory
      store.ingest(makePayload('repo-pure-memory'));
      expect(store.getRepos().length).toBe(1);
      expect(faultFs.callLog.length).toBe(0);

      // updatePolicy and clear run without fs
      store.updatePolicy({ failOnSeverity: 'LOW' });
      expect(store.getPolicy().failOnSeverity).toBe('LOW');
      expect(faultFs.callLog.length).toBe(0);

      store.clear();
      expect(store.getRepos().length).toBe(0);
      expect(faultFs.callLog.length).toBe(0);
    });
  });

  // F6: Stale temporary file cleanup precision
  describe('F6: Stale temp cleanup precision', () => {
    it('removes only genuine stale temps (>10m) and does not touch prefix-sharing files or directories', () => {
      // 1. Genuine stale temp (>10 min old)
      const staleTemp = `${primaryDb}.tmp.123.1700000000000.abc12345`;
      fs.writeFileSync(staleTemp, 'stale', 'utf8');
      const pastTime = (Date.now() - 12 * 60 * 1000) / 1000;
      fs.utimesSync(staleTemp, pastTime, pastTime);

      // 2. Genuine young temp (<10 min old)
      const youngTemp = `${primaryDb}.tmp.456.1700000000000.def67890`;
      fs.writeFileSync(youngTemp, 'young', 'utf8');
      const youngTime = (Date.now() - 60 * 1000) / 1000;
      fs.utimesSync(youngTemp, youngTime, youngTime);

      // 3. Stale backup temp (>10 min old)
      const staleBakTemp = `${primaryDb}.bak.tmp.99999999`;
      fs.writeFileSync(staleBakTemp, 'stale-bak', 'utf8');
      fs.utimesSync(staleBakTemp, pastTime, pastTime);

      // 4. File that merely shares prefix (`fleet-db.json.tmp-keep`)
      const prefixFile = `${primaryDb}.tmp-keep`;
      fs.writeFileSync(prefixFile, 'keep', 'utf8');
      fs.utimesSync(prefixFile, pastTime, pastTime);

      // 5. Directory named like temp (`fleet-db.json.tmp.dir`)
      const dirNamedTemp = `${primaryDb}.tmp.dir`;
      fs.mkdirSync(dirNamedTemp, { recursive: true });

      // Run FleetStore construction to trigger cleanup
      new FleetStore({ storageFile: primaryDb });

      // Assertions
      expect(fs.existsSync(staleTemp)).toBe(false); // Removed
      expect(fs.existsSync(staleBakTemp)).toBe(false); // Removed
      expect(fs.existsSync(youngTemp)).toBe(true); // Kept
      expect(fs.existsSync(prefixFile)).toBe(true); // Kept
      expect(fs.existsSync(dirNamedTemp)).toBe(true); // Kept
    });
  });

  // F7: Option aliasing (dbPath vs storageFile)
  describe('F7: Option aliasing (dbPath vs storageFile)', () => {
    it('persists with dbPath only, with storageFile only, and prefers storageFile when both provided', () => {
      // 1. dbPath only
      const path1 = path.join(tempDir, 'dbpath-only.json');
      const store1 = new FleetStore({ dbPath: path1 });
      store1.ingest(makePayload('repo-dbpath'));
      expect(fs.existsSync(path1)).toBe(true);

      // 2. storageFile only
      const path2 = path.join(tempDir, 'storagefile-only.json');
      const store2 = new FleetStore({ storageFile: path2 });
      store2.ingest(makePayload('repo-storagefile'));
      expect(fs.existsSync(path2)).toBe(true);

      // 3. Both provided: prefers storageFile
      const preferred = path.join(tempDir, 'preferred.json');
      const ignored = path.join(tempDir, 'ignored.json');
      const store3 = new FleetStore({ storageFile: preferred, dbPath: ignored });
      store3.ingest(makePayload('repo-both'));
      expect(fs.existsSync(preferred)).toBe(true);
      expect(fs.existsSync(ignored)).toBe(false);
    });
  });
});
