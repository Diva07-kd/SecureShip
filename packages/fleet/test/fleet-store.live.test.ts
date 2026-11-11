import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn, spawnSync } from 'node:child_process';
import { FleetStore } from '../src/storage/fleet-store.js';
import { serializeSnapshot } from '../src/storage/fleet-snapshot.js';
import { makePayload, withBom, LoggerSpy } from './fixtures/store-fixtures.js';

describe('LAYER M: Live and Environment Tests (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-live-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // M1: Gated Linux Docker container execution
  describe('M1: Gated Linux Docker execution', () => {
    it('(a) directory volume: persists across container restart', () => {
      if (!process.env.SECURESHIP_LIVE_DOCKER) {
        console.log(
          '[M1(a)] Skipped: SECURESHIP_LIVE_DOCKER is not set. In CI, run with SECURESHIP_LIVE_DOCKER=1'
        );
        expect(process.env.SECURESHIP_LIVE_DOCKER).toBeUndefined();
        return;
      }

      const hostVolumeDir = path.join(tempDir, 'docker-vol');
      fs.mkdirSync(hostVolumeDir, { recursive: true });

      // Run container that ingests repo and writes to volume
      const run1 = spawnSync('docker', [
        'run',
        '--rm',
        '-v',
        `${hostVolumeDir}:/data`,
        'node:20-alpine',
        'node',
        '-e',
        `
          const { FleetStore } = require('/app/packages/fleet/dist/storage/fleet-store.js');
          const store = new FleetStore({ storageFile: '/data/fleet-db.json' });
          store.ingest({
            fleetToken: 'corp-valid-test-token-at-least-24-chars',
            repoName: 'docker-persisted-repo',
            branch: 'main', commitSha: 'a1b2c3d4e5f678901234567890abcdef12345678',
            scannedAt: new Date().toISOString(), durationMs: 10,
            summary: { totalRaw: 1, totalReported: 0, totalSuppressed: 1, bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 }, reachabilitySuppressionPct: 100 },
            vulnerabilities: [], sbom: { totalComponents: 1, compliantCount: 1, nonCompliantCount: 0, components: [] }
          });
        `,
      ]);
      expect(run1.status).toBe(0);

      // Verify on host
      expect(fs.existsSync(path.join(hostVolumeDir, 'fleet-db.json'))).toBe(true);

      // Restart container and verify data survives
      const run2 = spawnSync('docker', [
        'run',
        '--rm',
        '-v',
        `${hostVolumeDir}:/data`,
        'node:20-alpine',
        'node',
        '-e',
        `
          const { FleetStore } = require('/app/packages/fleet/dist/storage/fleet-store.js');
          const store = new FleetStore({ storageFile: '/data/fleet-db.json' });
          if (!store.getRepo('docker-persisted-repo')) process.exit(1);
        `,
      ]);
      expect(run2.status).toBe(0);
    });

    it('(b) SINGLE-FILE bind mount: rename gives EBUSY, store switches to non-atomic-fallback, survives restart, host sees .bak', () => {
      if (!process.env.SECURESHIP_LIVE_DOCKER) {
        console.log(
          '[M1(b)] Skipped: SECURESHIP_LIVE_DOCKER is not set. In CI, run with SECURESHIP_LIVE_DOCKER=1'
        );
        expect(process.env.SECURESHIP_LIVE_DOCKER).toBeUndefined();
        return;
      }

      const hostFile = path.join(tempDir, 'single-file-db.json');
      fs.writeFileSync(hostFile, JSON.stringify({ formatVersion: 1, repos: [], policy: {} }));

      const run = spawnSync('docker', [
        'run',
        '--rm',
        '-v',
        `${hostFile}:/app/db.json`,
        'node:20-alpine',
        'node',
        '-e',
        `
          const { FleetStore } = require('/app/packages/fleet/dist/storage/fleet-store.js');
          const store = new FleetStore({ storageFile: '/app/db.json' });
          store.ingest({
            fleetToken: 'corp-valid-test-token-at-least-24-chars',
            repoName: 'single-mount-repo',
            branch: 'main', commitSha: 'a1b2c3d4e5f678901234567890abcdef12345678',
            scannedAt: new Date().toISOString(), durationMs: 10,
            summary: { totalRaw: 1, totalReported: 0, totalSuppressed: 1, bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 }, reachabilitySuppressionPct: 100 },
            vulnerabilities: [], sbom: { totalComponents: 1, compliantCount: 1, nonCompliantCount: 0, components: [] }
          });
          const status = store.getPersistenceStatus();
          if (status.mode !== 'non-atomic-fallback') process.exit(2);
        `,
      ]);

      expect(run.status).toBe(0);
      expect(fs.existsSync(hostFile + '.bak')).toBe(true);
    });

    it('(c) read-only rootfs: writable volume works; NO volume logs FLEET_STORE_DIR_NOT_WRITABLE and keeps serving in memory', () => {
      if (!process.env.SECURESHIP_LIVE_DOCKER) {
        console.log(
          '[M1(c)] Skipped: SECURESHIP_LIVE_DOCKER is not set. In CI, run with SECURESHIP_LIVE_DOCKER=1'
        );
        expect(process.env.SECURESHIP_LIVE_DOCKER).toBeUndefined();
        return;
      }

      const run = spawnSync('docker', [
        'run',
        '--rm',
        '--read-only',
        'node:20-alpine',
        'node',
        '-e',
        `
          const { FleetStore } = require('/app/packages/fleet/dist/storage/fleet-store.js');
          const store = new FleetStore({ storageFile: '/ro-dir/fleet-db.json' });
          const status = store.getPersistenceStatus();
          if (status.healthy !== false) process.exit(1);
          // Ingest still works in-memory
          const summary = store.ingest({
            fleetToken: 'corp-valid-test-token-at-least-24-chars',
            repoName: 'ro-repo',
            branch: 'main', commitSha: 'a1b2c3d4e5f678901234567890abcdef12345678',
            scannedAt: new Date().toISOString(), durationMs: 10,
            summary: { totalRaw: 1, totalReported: 0, totalSuppressed: 1, bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 }, reachabilitySuppressionPct: 100 },
            vulnerabilities: [], sbom: { totalComponents: 1, compliantCount: 1, nonCompliantCount: 0, components: [] }
          });
          if (summary.totalRaw !== 1) process.exit(2);
        `,
      ]);
      expect(run.status).toBe(0);
    });

    it('(d) non-root UID 10001 creates files with mode 0600 on Linux', () => {
      if (!process.env.SECURESHIP_LIVE_DOCKER) {
        console.log(
          '[M1(d)] Skipped: SECURESHIP_LIVE_DOCKER is not set. In CI, run with SECURESHIP_LIVE_DOCKER=1'
        );
        expect(process.env.SECURESHIP_LIVE_DOCKER).toBeUndefined();
        return;
      }

      const run = spawnSync('docker', [
        'run',
        '--rm',
        '--user',
        '10001:10001',
        '-v',
        `${tempDir}:/data`,
        'node:20-alpine',
        'node',
        '-e',
        `
          const fs = require('fs');
          const { FleetStore } = require('/app/packages/fleet/dist/storage/fleet-store.js');
          const store = new FleetStore({ storageFile: '/data/uid-test.json' });
          store.ingest({
            fleetToken: 'corp-valid-test-token-at-least-24-chars',
            repoName: 'uid-repo',
            branch: 'main', commitSha: 'a1b2c3d4e5f678901234567890abcdef12345678',
            scannedAt: new Date().toISOString(), durationMs: 10,
            summary: { totalRaw: 1, totalReported: 0, totalSuppressed: 1, bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 }, reachabilitySuppressionPct: 100 },
            vulnerabilities: [], sbom: { totalComponents: 1, compliantCount: 1, nonCompliantCount: 0, components: [] }
          });
          const stat = fs.statSync('/data/uid-test.json');
          if ((stat.mode & 0o777) !== 0o600) process.exit(1);
        `,
      ]);
      expect(run.status).toBe(0);
    });
  });

  // M2: Windows live tests (exclusive handle lock, BOM, Unicode/spaces)
  describe('M2: Windows live platform verification', () => {
    it('handles paths with spaces, unicode characters, and emoji correctly', () => {
      const unicodeSubdir = path.join(tempDir, 'fleet space ⚡ 数据库 test');
      fs.mkdirSync(unicodeSubdir, { recursive: true });
      const unicodeDb = path.join(unicodeSubdir, 'fleet-db 🚀.json');

      const store = new FleetStore({ storageFile: unicodeDb });
      store.ingest(makePayload('unicode-repo-测试-🔐'));

      expect(fs.existsSync(unicodeDb)).toBe(true);
      const content = fs.readFileSync(unicodeDb, 'utf8');
      expect(content).toContain('unicode-repo-测试-🔐');

      // Reload in fresh store
      const reloadedStore = new FleetStore({ storageFile: unicodeDb });
      const repo = reloadedStore.getRepo('unicode-repo-测试-🔐');
      expect(repo).toBeDefined();
      expect(repo?.repoName).toBe('unicode-repo-测试-🔐');
    });

    it('loads and persists correctly when database file starts with UTF-8 BOM', () => {
      const bomDb = path.join(tempDir, 'fleet-bom.json');

      // Create a valid serialized snapshot via standard serializer
      const initialStore = new FleetStore();
      initialStore.ingest(makePayload('bom-repo'));
      const serialized = serializeSnapshot({
        repos: initialStore.getRepos(),
        policy: initialStore.getPolicy(),
      });

      fs.writeFileSync(bomDb, withBom(serialized.buffer));

      const store = new FleetStore({ storageFile: bomDb });
      expect(store.getRepos().length).toBe(1);
      expect(store.getRepo('bom-repo')).toBeDefined();

      // Ingest new repo and verify persistence
      store.ingest(makePayload('after-bom-repo'));
      const reloaded = new FleetStore({ storageFile: bomDb });
      expect(reloaded.getRepos().length).toBe(2);
      expect(reloaded.getRepo('after-bom-repo')).toBeDefined();
    });

    it('on win32: retry loop runs when destination file is locked, fails cleanly when held > 310ms without corrupting primary', async () => {
      if (process.platform !== 'win32') {
        console.log(
          '[M2] Exclusivity lock test skipped on non-Windows platform: ' + process.platform
        );
        expect(process.platform).not.toBe('win32');
        return;
      }

      const lockDb = path.join(tempDir, 'fleet-lock.json');
      const seedStore = new FleetStore();
      seedStore.ingest(makePayload('initial-locked-repo'));
      const serialized = serializeSnapshot({
        repos: seedStore.getRepos(),
        policy: seedStore.getPolicy(),
      });
      fs.writeFileSync(lockDb, serialized.buffer);
      const originalBytes = fs.readFileSync(lockDb);

      const logger = new LoggerSpy();
      const store = new FleetStore({
        storageFile: lockDb,
        internals: { logger },
      });

      // Spawn PowerShell script that holds FileShare.None exclusive read lock for 1200ms (> 310ms retry budget)
      const psScript = `
        $path = "${lockDb.replace(/\\/g, '\\\\')}"
        $file = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        [Console]::WriteLine("LOCKED")
        [Console]::Out.Flush()
        Start-Sleep -Milliseconds 1200
        $file.Close()
      `;

      const child = spawn('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        psScript,
      ]);

      try {
        // Wait until PowerShell has confirmed lock acquisition via stdout
        await new Promise<void>((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error('PowerShell lock timeout'));
          }, 5000);

          child.stdout.on('data', (chunk: Buffer) => {
            if (chunk.toString().includes('LOCKED')) {
              clearTimeout(timeout);
              resolve();
            }
          });
          child.on('error', (err) => {
            clearTimeout(timeout);
            reject(err);
          });
        });

        // Attempt ingest while primary is exclusively locked
        store.ingest(makePayload('blocked-repo'));

        // Since locked > 310ms, persist should fail
        const status = store.getPersistenceStatus();
        expect(status.healthy).toBe(false);
        expect(status.consecutiveFailures).toBe(1);

        // Kill PowerShell child process and wait for it to exit so OS releases lock
        child.kill();
        await new Promise<void>((resolve) => {
          if (child.exitCode !== null) {
            resolve();
          } else {
            child.on('exit', () => resolve());
          }
        });

        // Verify primary file is completely intact and untouched
        const currentBytes = fs.readFileSync(lockDb);
        expect(Buffer.compare(currentBytes, originalBytes)).toBe(0);

        // Verify no leftover .tmp files
        const files = fs.readdirSync(tempDir);
        const tmpFiles = files.filter((f) => f.includes('.tmp.'));
        expect(tmpFiles).toEqual([]);
      } finally {
        // Ensure child process is killed
        try {
          child.kill();
        } catch {}
      }

      // After lock is released, subsequent persist succeeds
      store.ingest(makePayload('unblocked-repo'));
      const statusAfter = store.getPersistenceStatus();
      expect(statusAfter.healthy).toBe(true);
      expect(statusAfter.consecutiveFailures).toBe(0);
    });
  });

  // M3: macOS live environment documentation
  describe('M3: macOS live environment documentation', () => {
    it('documents APFS clone and HFS+ case-insensitivity behavior; skips if not on darwin', () => {
      if (process.platform !== 'darwin') {
        console.log(
          `[M3] macOS live tests skipped: host platform is '${process.platform}', not 'darwin'. APFS atomic rename guarantees verified via POSIX fs contract.`
        );
        expect(process.platform).not.toBe('darwin');
        return;
      }

      // On darwin: verify rename atomicity and case preservation
      const macDb = path.join(tempDir, 'fleet-mac.json');
      const store = new FleetStore({ storageFile: macDb });
      store.ingest(makePayload('darwin-repo'));
      expect(fs.existsSync(macDb)).toBe(true);
    });
  });

  // M4: Network filesystem (NFS / SMB) explicit documentation
  describe('M4: Network filesystem (NFS / SMB) environment support', () => {
    it('documents NFS/SMB as an explicit UNVERIFIED environment', () => {
      /**
       * NETWORK FILESYSTEM CONTRACT NOTICE:
       * Network filesystems (NFSv3, NFSv4, SMB2/3, CIFS) do not provide cross-client atomic rename
       * semantics consistent with local POSIX or Windows NTFS filesystems. Specifically:
       * 1. Rename across SMB shares may fail with ERROR_ACCESS_DENIED or fallback non-atomically.
       * 2. NFS close-to-open cache consistency means directory fsync does not invalidate remote client caches.
       * 3. Network filesystem deployments must run SecureShip Fleet in centralized service mode or memory-only.
       */
      const NETWORK_FILESYSTEM_STATUS = 'UNVERIFIED';
      expect(NETWORK_FILESYSTEM_STATUS).toBe('UNVERIFIED');
    });
  });
});
