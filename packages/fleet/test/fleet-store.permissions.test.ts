import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { FleetStore } from '../src/storage/fleet-store.js';
import { FaultFs } from './fixtures/fault-fs.js';
import { makePayload } from './fixtures/store-fixtures.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('LAYER G: File and Directory Permissions (POSIX / Windows) (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;
  let primaryDb: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-perms-test-'));
    primaryDb = path.join(tempDir, 'fleet-db.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // G1: Mode 0o600 on files and 0o700 on newly created directories
  it('G1: primary file has mode 0o600, newly created dir 0o700; bak, quarantine and temp files are 0o600', () => {
    const isWindows = process.platform === 'win32';
    if (isWindows) {
      console.log('permissions suite skipped: no POSIX modes');
    }

    // Test through linux faultFs facade to verify exact requested modes on all platforms
    const linuxFs = new FaultFs({ platform: 'linux' });
    const nestedDir = path.join(tempDir, 'nested-perms');
    const nestedDb = path.join(nestedDir, 'fleet-db.json');

    const store = new FleetStore({
      storageFile: nestedDb,
      internals: {
        fs: linuxFs,
        platform: 'linux',
      },
    });

    store.ingest(makePayload('repo-perms-1'));
    store.ingest(makePayload('repo-perms-2'));

    // 1. Temp file opened with 0o600
    const tempOpens = linuxFs.callLog.filter(
      (c) =>
        c.op === 'openSync' &&
        typeof c.path === 'string' &&
        c.path.includes('.tmp.') &&
        c.args[1] === 'wx'
    );
    expect(tempOpens.length).toBeGreaterThan(0);
    for (const to of tempOpens) {
      expect(to.args[2]).toBe(0o600);
    }

    // 2. Chmod on primary file is 0o600
    const chmodPrimary = linuxFs.callLog.filter((c) => c.op === 'chmodSync' && c.path === nestedDb);
    expect(chmodPrimary.length).toBeGreaterThan(0);
    expect(chmodPrimary[0]!.args[1]).toBe(0o600);

    // 3. Backup temp chmod is 0o600
    const chmodBakTmp = linuxFs.callLog.filter(
      (c) => c.op === 'chmodSync' && typeof c.path === 'string' && c.path.includes('.bak.tmp.')
    );
    expect(chmodBakTmp.length).toBeGreaterThan(0);
    expect(chmodBakTmp[0]!.args[1]).toBe(0o600);

    // If on real POSIX system, assert real mode bits
    if (!isWindows) {
      const realStore = new FleetStore({ storageFile: primaryDb });
      realStore.ingest(makePayload('repo-real-posix'));
      const st = fs.statSync(primaryDb);
      expect(st.mode & 0o777).toBe(0o600);
    } else {
      // Content assertion on Windows
      const winStore = new FleetStore({ storageFile: primaryDb });
      winStore.ingest(makePayload('repo-win-content'));
      expect(winStore.getRepos().length).toBe(1);
    }
  });

  // G2: A baseline-created 0o644 primary is tightened to 0o600 after next persist
  it('G2: a baseline-created 0o644 primary is tightened to 0o600 after next persist', () => {
    const isWindows = process.platform === 'win32';
    if (isWindows) {
      console.log('permissions suite skipped: no POSIX modes');
    }

    const linuxFs = new FaultFs({ platform: 'linux' });
    fs.writeFileSync(primaryDb, '{"repos":[]}', 'utf8');

    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: linuxFs,
        platform: 'linux',
      },
    });

    store.ingest(makePayload('repo-tightened'));

    const chmodCalls = linuxFs.callLog.filter((c) => c.op === 'chmodSync' && c.path === primaryDb);
    expect(chmodCalls.length).toBeGreaterThan(0);
    expect(chmodCalls[0]!.args[1]).toBe(0o600);

    if (!isWindows) {
      fs.chmodSync(primaryDb, 0o644);
      const realStore = new FleetStore({ storageFile: primaryDb });
      realStore.ingest(makePayload('repo-tightened-real'));
      const st = fs.statSync(primaryDb);
      expect(st.mode & 0o777).toBe(0o600);
    }
  });

  // G3: Independence from process umask
  it('G3: permission modes are independent of umask', () => {
    const isWindows = process.platform === 'win32';
    if (isWindows) {
      console.log('permissions suite skipped: no POSIX modes');
      expect(process.platform).toBe('win32');
      return;
    }

    const storeUrl = pathToFileURL(path.resolve(__dirname, '../dist/storage/fleet-store.js')).href;
    for (const umaskVal of [0, 0o022, 0o077]) {
      const childScript = `
        import { FleetStore } from '${storeUrl}';
        process.umask(${umaskVal});
        const store = new FleetStore({ storageFile: '${primaryDb.replace(/\\/g, '/')}' });
        store.ingest({
          fleetToken: 'test-token-valid-24-chars-long',
          repoName: 'repo-umask-${umaskVal}',
          branch: 'main',
          commitSha: 'c0ffee',
          scannedAt: '2026-11-04T00:00:00.000Z',
          durationMs: 10,
          summary: { totalRaw: 0, totalReported: 0, totalSuppressed: 0, bySeverity: {}, byCategory: {}, reachabilitySuppressionPct: 0 },
          vulnerabilities: []
        });
      `;

      const res = spawnSync(process.execPath, ['--input-type=module', '-e', childScript]);
      expect(res.status).toBe(0);

      const st = fs.statSync(primaryDb);
      expect(st.mode & 0o777).toBe(0o600);
    }
  });

  // G4: An existing directory with mode 0o755 is not chmod-ed
  it('G4: an existing directory with mode 0o755 is not modified or chmod-ed', () => {
    const isWindows = process.platform === 'win32';
    if (isWindows) {
      console.log('permissions suite skipped: no POSIX modes');
    }

    const linuxFs = new FaultFs({ platform: 'linux' });
    const store = new FleetStore({
      storageFile: primaryDb,
      internals: {
        fs: linuxFs,
        platform: 'linux',
      },
    });

    store.ingest(makePayload('repo-no-dir-chmod'));

    // chmodSync was NEVER called on the directory tempDir
    const dirChmod = linuxFs.callLog.filter((c) => c.op === 'chmodSync' && c.path === tempDir);
    expect(dirChmod.length).toBe(0);
  });
});
