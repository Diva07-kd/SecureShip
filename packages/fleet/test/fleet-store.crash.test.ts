import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { FleetStore } from '../src/storage/fleet-store.js';
import { BaselineFleetStore } from './fixtures/baseline-fleet-store.js';
import { makePayload } from './fixtures/store-fixtures.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CRASH_CHILD = path.resolve(__dirname, 'fixtures/crash-child.mjs');

interface OpInfo {
  op: string;
  path: string;
  k: number;
  isWrite: boolean;
}

function runChildSync(
  args: string[],
  timeoutMs = 15000
): { code: number | null; signal: string | null; stdout: string; stderr: string } {
  const res = spawnSync(process.execPath, ['--experimental-strip-types', CRASH_CHILD, ...args], {
    timeout: timeoutMs,
    encoding: 'utf8',
  });
  return {
    code: res.status,
    signal: res.signal,
    stdout: res.stdout || '',
    stderr: res.stderr || '',
  };
}

describe('LAYER C: Crash Consistency with Real Processes (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;
  let dbPath: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-crash-test-'));
    dbPath = path.join(tempDir, 'fleet-db.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // C1: Exhaustive crash-point test on remediated FleetStore
  describe('C1: Exhaustive crash-point matrix on FleetStore', () => {
    it('ingest operation: every crash point recovers {A,B} or {A,B,C} with valid snapshot and never empty', () => {
      // Step 1: Dry run to discover all K operations
      const dry = runChildSync(['dry-run', tempDir, 'ingest']);
      expect(dry.code).toBe(0);
      const ops: OpInfo[] = JSON.parse(dry.stdout.trim());
      expect(ops.length).toBeGreaterThan(5);

      const opNames = ops.map((o) => `${o.k}:${o.op}`).join(', ');
      console.log(`[C1 Ingest Matrix] ${ops.length} crash points: ${opNames}`);

      for (const op of ops) {
        // Variant 1: Kill BEFORE op k
        {
          const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-c1-ingest-'));
          const runDb = path.join(runDir, 'fleet-db.json');
          try {
            runChildSync(['kill-point', runDir, 'ingest', String(op.k), 'before', 'remediated']);

            const store = new FleetStore({ storageFile: runDb });
            const repos = store
              .getRepos()
              .map((r) => r.repoName)
              .sort();
            const report = store.getLoadReport();

            // Must be {A,B} or {A,B,C}
            const isAB = repos.length === 2 && repos[0] === 'repo-A' && repos[1] === 'repo-B';
            const isABC =
              repos.length === 3 &&
              repos[0] === 'repo-A' &&
              repos[1] === 'repo-B' &&
              repos[2] === 'repo-C';
            expect(isAB || isABC).toBe(true);

            expect(report.source).not.toBe('empty-after-corruption');
            expect(['primary', 'backup'].includes(report.source)).toBe(true);
            expect(store.getPolicy().failOnSeverity).toBe('HIGH');
          } finally {
            try {
              fs.rmSync(runDir, { recursive: true, force: true });
            } catch {}
          }
        }

        // Variant 2: Kill AFTER half write if this is a write operation
        if (op.isWrite) {
          const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-c1-ingest-half-'));
          const runDb = path.join(runDir, 'fleet-db.json');
          try {
            runChildSync([
              'kill-point',
              runDir,
              'ingest',
              String(op.k),
              'after-half-write',
              'remediated',
            ]);

            const store = new FleetStore({ storageFile: runDb });
            const repos = store
              .getRepos()
              .map((r) => r.repoName)
              .sort();
            const report = store.getLoadReport();

            const isAB = repos.length === 2 && repos[0] === 'repo-A' && repos[1] === 'repo-B';
            const isABC =
              repos.length === 3 &&
              repos[0] === 'repo-A' &&
              repos[1] === 'repo-B' &&
              repos[2] === 'repo-C';
            expect(isAB || isABC).toBe(true);
            expect(report.source).not.toBe('empty-after-corruption');
          } finally {
            try {
              fs.rmSync(runDir, { recursive: true, force: true });
            } catch {}
          }
        }
      }
    });

    it('updatePolicy operation: every crash point recovers {P0} or {P1} with {A,B} intact', () => {
      const dry = runChildSync(['dry-run', tempDir, 'updatePolicy']);
      expect(dry.code).toBe(0);
      const ops: OpInfo[] = JSON.parse(dry.stdout.trim());

      for (const op of ops) {
        const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-c1-policy-'));
        const runDb = path.join(runDir, 'fleet-db.json');
        try {
          runChildSync([
            'kill-point',
            runDir,
            'updatePolicy',
            String(op.k),
            'before',
            'remediated',
          ]);

          const store = new FleetStore({ storageFile: runDb });
          const policy = store.getPolicy();
          const report = store.getLoadReport();

          expect(policy.failOnSeverity === 'HIGH' || policy.failOnSeverity === 'CRITICAL').toBe(
            true
          );
          expect(report.source).not.toBe('empty-after-corruption');
          expect(store.getRepos().length).toBe(2);
        } finally {
          try {
            fs.rmSync(runDir, { recursive: true, force: true });
          } catch {}
        }
      }
    });

    it('clear operation: every crash point recovers {A,B} or empty set without corruption', () => {
      const dry = runChildSync(['dry-run', tempDir, 'clear']);
      expect(dry.code).toBe(0);
      const ops: OpInfo[] = JSON.parse(dry.stdout.trim());

      for (const op of ops) {
        const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-c1-clear-'));
        const runDb = path.join(runDir, 'fleet-db.json');
        try {
          runChildSync(['kill-point', runDir, 'clear', String(op.k), 'before', 'remediated']);

          const store = new FleetStore({ storageFile: runDb });
          const count = store.getRepos().length;
          expect(count === 2 || count === 0).toBe(true);
        } finally {
          try {
            fs.rmSync(runDir, { recursive: true, force: true });
          } catch {}
        }
      }
    });

    it('first-write operation: every crash point recovers empty or {A} cleanly', () => {
      const dry = runChildSync(['dry-run', tempDir, 'first-write']);
      expect(dry.code).toBe(0);
      const ops: OpInfo[] = JSON.parse(dry.stdout.trim());

      for (const op of ops) {
        const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-c1-first-'));
        const runDb = path.join(runDir, 'fleet-db.json');
        try {
          runChildSync(['kill-point', runDir, 'first-write', String(op.k), 'before', 'remediated']);

          const store = new FleetStore({ storageFile: runDb });
          const count = store.getRepos().length;
          expect(count === 0 || count === 1).toBe(true);
        } finally {
          try {
            fs.rmSync(runDir, { recursive: true, force: true });
          } catch {}
        }
      }
    });
  });

  // C2: Red proof on baseline implementation
  it('C2: baseline implementation loses data on write crash point (loads EMPTY store)', () => {
    // 1. Setup baseline store with {A, B}
    const baselineSetup = new BaselineFleetStore({ storageFile: dbPath });
    baselineSetup.ingest(makePayload('repo-A'));
    baselineSetup.ingest(makePayload('repo-B'));
    expect(baselineSetup.getRepos().length).toBe(2);

    // 2. Crash baseline during half-write of ingest
    runChildSync(['kill-point', tempDir, 'ingest', '1', 'after-half-write', 'baseline']);

    // 3. Load with BaselineFleetStore
    const crashedBaseline = new BaselineFleetStore({ storageFile: dbPath });

    // RED PROOF: Baseline loaded an EMPTY store because JSON.parse failed and threw away state!
    expect(crashedBaseline.getRepos().length).toBe(0);
  });

  // C3: Randomised kill loop with seeded PRNG (40 iterations)
  it('C3: randomised SIGKILL loop over continuous ingests preserves consistency (loaded >= lastAcked)', async () => {
    // Deterministic PRNG (Linear Congruential Generator)
    const seed = 133742;
    let state = seed;
    function nextRand(): number {
      state = (state * 1664525 + 1013904223) % 4294967296;
      return state / 4294967296;
    }

    const iterations = Number(process.env.CRASH_TEST_ITERATIONS) || 40;
    console.log(`[C3 Random Kill Loop] Running with seed=${seed}, iterations=${iterations}`);

    for (let i = 0; i < iterations; i++) {
      const runDir = fs.mkdtempSync(path.join(os.tmpdir(), `secureship-c3-${i}-`));
      const runDb = path.join(runDir, 'fleet-db.json');
      let child: ChildProcess | null = null;

      try {
        child = spawn(
          process.execPath,
          ['--experimental-strip-types', CRASH_CHILD, 'random-loop', runDir, 'remediated'],
          { stdio: ['ignore', 'pipe', 'pipe'] }
        );

        let lastAcked = 0;
        child.stdout?.on('data', (d) => {
          const text = d.toString('utf8');
          const matches = text.matchAll(/ACK\s+(\d+)/g);
          for (const m of matches) {
            const n = parseInt(m[1], 10);
            if (n > lastAcked) lastAcked = n;
          }
        });

        // Wait until at least 2 ACKs have arrived
        const startTime = Date.now();
        while (lastAcked < 2 && Date.now() - startTime < 8000) {
          await new Promise((r) => setTimeout(r, 20));
        }

        // Random jitter between 5ms and 50ms before kill
        const jitterMs = 5 + Math.floor(nextRand() * 45);
        await new Promise((r) => setTimeout(r, jitterMs));

        // Kill child process
        const ackAtKill = lastAcked;
        child.kill('SIGKILL');

        // Wait for child exit
        await new Promise<void>((resolve) => {
          child?.on('exit', () => resolve());
          setTimeout(resolve, 2000);
        });

        // Construct fresh FleetStore on disk
        const store = new FleetStore({ storageFile: runDb });
        const loadedCount = store.getRepos().length;
        const report = store.getLoadReport();

        expect(report.source).not.toBe('empty-after-corruption');
        expect(loadedCount).toBeGreaterThanOrEqual(ackAtKill);
      } finally {
        if (child && !child.killed) {
          child.kill('SIGKILL');
        }
        try {
          fs.rmSync(runDir, { recursive: true, force: true });
        } catch {}
      }
    }
  }, 60000);

  // C4: Kill during heal-after-recovery and backup rotation
  it('C4: process kill during heal-after-recovery and backup rotation leaves valid snapshot on restart', () => {
    // 1. Process kill during heal-after-recovery
    const healDry = runChildSync(['dry-run', tempDir, 'heal']);
    expect(healDry.code).toBe(0);
    const healOps: OpInfo[] = JSON.parse(healDry.stdout.trim());
    expect(healOps.length).toBeGreaterThan(0);

    for (const op of healOps.slice(0, 3)) {
      const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-c4-heal-'));
      const runDb = path.join(runDir, 'fleet-db.json');
      try {
        runChildSync(['kill-point', runDir, 'heal', String(op.k), 'before', 'remediated']);

        // Fresh restart must recover cleanly from backup
        const store = new FleetStore({ storageFile: runDb });
        expect(store.getRepos().length).toBe(1);
        expect(store.getRepos()[0]?.repoName).toBe('repo-A');
        expect(store.getLoadReport().source).toBe('backup');
      } finally {
        try {
          fs.rmSync(runDir, { recursive: true, force: true });
        } catch {}
      }
    }

    // 2. Process kill during backup rotation
    const bakDry = runChildSync(['dry-run', tempDir, 'bak-rotation']);
    expect(bakDry.code).toBe(0);
    const bakOps: OpInfo[] = JSON.parse(bakDry.stdout.trim());
    const rotOps = bakOps.filter((o) => o.op === 'copyFileSync' || o.op === 'renameSync');
    expect(rotOps.length).toBeGreaterThan(0);

    for (const op of rotOps) {
      const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-c4-rot-'));
      const runDb = path.join(runDir, 'fleet-db.json');
      try {
        runChildSync(['kill-point', runDir, 'bak-rotation', String(op.k), 'before', 'remediated']);

        // Fresh restart must still load a valid snapshot ({A,B} or {A,B,C})
        const store = new FleetStore({ storageFile: runDb });
        const repos = store
          .getRepos()
          .map((r) => r.repoName)
          .sort();
        const isAB = repos.length === 2 && repos[0] === 'repo-A' && repos[1] === 'repo-B';
        const isABC =
          repos.length === 3 &&
          repos[0] === 'repo-A' &&
          repos[1] === 'repo-B' &&
          repos[2] === 'repo-C';
        expect(isAB || isABC).toBe(true);
        expect(store.getLoadReport().source).not.toBe('empty-after-corruption');
      } finally {
        try {
          fs.rmSync(runDir, { recursive: true, force: true });
        } catch {}
      }
    }
  });

  // C5: Stale temporary file cleanup on restart
  it('C5: removes stale temps older than 10 minutes and preserves younger temps', () => {
    // Create database
    const store = new FleetStore({ storageFile: dbPath });
    store.ingest(makePayload('repo-c5'));

    // Create stale temp (older than 15 minutes)
    const staleTemp = `${dbPath}.tmp.9999.1700000000000.aabbccdd`;
    fs.writeFileSync(staleTemp, 'stale', 'utf8');
    const pastTime = (Date.now() - 15 * 60 * 1000) / 1000;
    fs.utimesSync(staleTemp, pastTime, pastTime);

    // Create young temp (1 minute old)
    const youngTemp = `${dbPath}.tmp.8888.1700000000000.11223344`;
    fs.writeFileSync(youngTemp, 'young', 'utf8');
    const youngTime = (Date.now() - 60 * 1000) / 1000;
    fs.utimesSync(youngTemp, youngTime, youngTime);

    // Restart FleetStore on directory
    new FleetStore({ storageFile: dbPath });

    // Stale temp was removed
    expect(fs.existsSync(staleTemp)).toBe(false);

    // Young temp was preserved
    expect(fs.existsSync(youngTemp)).toBe(true);
  });
});
