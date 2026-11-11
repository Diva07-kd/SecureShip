import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { FleetStore } from '../src/storage/fleet-store.js';
import { makePayload, v1File, LoggerSpy } from './fixtures/store-fixtures.js';

describe('LAYER E: Backup Rotation Semantics (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;
  let primaryDb: string;
  let bakDb: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-rotation-test-'));
    primaryDb = path.join(tempDir, 'fleet-db.json');
    bakDb = path.join(tempDir, 'fleet-db.json.bak');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // E1: Sequence of 5 ingests: backup equals previous primary bytes exactly S(n-1)
  it('E1: verifies sequence of 5 ingests where .bak equals previous primary bytes exactly', () => {
    const store = new FleetStore({ storageFile: primaryDb });
    const snapshots: Buffer[] = [];

    for (let i = 1; i <= 5; i++) {
      store.ingest(makePayload(`repo-${i}`));
      const primaryBytes = fs.readFileSync(primaryDb);
      snapshots.push(primaryBytes);

      if (i === 1) {
        // First write: no backup should exist yet
        expect(fs.existsSync(bakDb)).toBe(false);
      } else {
        // Subsequent writes: backup equals exact bytes of previous persist
        expect(fs.existsSync(bakDb)).toBe(true);
        const bakBytes = fs.readFileSync(bakDb);
        const expectedPrevious = snapshots[i - 2]!;
        expect(Buffer.compare(bakBytes, expectedPrevious)).toBe(0);
      }
    }
  });

  // E2: Corrupt primary externally while store runs: existing backup is NOT overwritten
  it('E2: corrupt primary externally before ingest: backup preserved, corrupt primary quarantined, new primary written', () => {
    const logger = new LoggerSpy();
    const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

    // Ingest repo-1 and repo-2 to establish good primary and good backup
    store.ingest(makePayload('repo-1'));
    store.ingest(makePayload('repo-2'));
    const goodBakBytes = fs.readFileSync(bakDb);

    // Corrupt primary file externally (truncate)
    const corruptBytes = Buffer.from('{"repos": [corrupt-data', 'utf8');
    fs.writeFileSync(primaryDb, corruptBytes);

    // Now ingest repo-3: store should detect corruption, NOT overwrite backup, quarantine corrupt primary
    store.ingest(makePayload('repo-3'));

    // 1. Existing backup was preserved
    const currentBakBytes = fs.readFileSync(bakDb);
    expect(Buffer.compare(currentBakBytes, goodBakBytes)).toBe(0);

    // 2. Corrupt primary was quarantined
    const entries = fs.readdirSync(tempDir);
    const qFiles = entries.filter((e) => e.includes('.corrupt-'));
    expect(qFiles.length).toBe(1);
    const qBytes = fs.readFileSync(path.join(tempDir, qFiles[0]!));
    expect(Buffer.compare(qBytes, corruptBytes)).toBe(0);

    // 3. Warning logged
    expect(logger.hasCode('FLEET_STORE_PRIMARY_CORRUPT')).toBe(true);

    // 4. New primary is valid and complete
    const reloaded = new FleetStore({ storageFile: primaryDb });
    expect(reloaded.getRepo('repo-3')).toBeDefined();
    expect(reloaded.getLoadReport().source).toBe('primary');
  });

  // E3: Modify primary externally with valid different snapshot (another writer)
  it('E3: external valid modification triggers FLEET_STORE_EXTERNAL_MODIFICATION and rotates external state to backup (last-writer-wins)', () => {
    const logger = new LoggerSpy();
    const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

    store.ingest(makePayload('store1-repo'));

    // Another process writes an external valid snapshot to primaryDb
    const externalRepo = makePayload('external-writer-repo');
    const externalStore = new FleetStore();
    const externalSummary = externalStore.ingest(externalRepo);
    const externalContent = v1File({ repos: [externalSummary] });
    fs.writeFileSync(primaryDb, externalContent, 'utf8');
    const externalBytes = fs.readFileSync(primaryDb);

    // Now this store ingests another repo
    store.ingest(makePayload('store1-second-repo'));

    // 1. Multi-writer detection logged
    expect(logger.hasCode('FLEET_STORE_EXTERNAL_MODIFICATION')).toBe(true);

    // 2. The valid external file was safely rotated into backup before overwriting
    const currentBakBytes = fs.readFileSync(bakDb);
    expect(Buffer.compare(currentBakBytes, externalBytes)).toBe(0);

    // 3. Current primary contains this store's mutations (last writer wins)
    const reloaded = new FleetStore({ storageFile: primaryDb });
    expect(reloaded.getRepo('store1-second-repo')).toBeDefined();
  });

  // E4: First persist after recovery does not rotate corrupt primary into backup
  it('E4: after recovery from backup, the first persist does NOT rotate the corrupt primary into backup', () => {
    // Setup good backup
    const s0Payload = makePayload('repo-s0');
    const tempStore = new FleetStore();
    const s0Summary = tempStore.ingest(s0Payload);
    const goodBakContent = v1File({ repos: [s0Summary] });
    fs.writeFileSync(bakDb, goodBakContent, 'utf8');
    const goodBakBytes = fs.readFileSync(bakDb);

    // Primary is corrupt
    fs.writeFileSync(primaryDb, 'broken-primary', 'utf8');

    // Load store: recovers from backup
    const store = new FleetStore({ storageFile: primaryDb });
    expect(store.getLoadReport().source).toBe('backup');

    // Right after recovery, the corrupt primary was NOT rotated into backup
    const bakRightAfterLoad = fs.readFileSync(bakDb);
    expect(Buffer.compare(bakRightAfterLoad, goodBakBytes)).toBe(0);

    // Now ingest a new repo: primary holds the healed state (repo-s0), which is now safely rotated
    store.ingest(makePayload('repo-post-recover'));

    // Backup is valid snapshot containing repo-s0, NEVER broken-primary
    const bakAfter = fs.readFileSync(bakDb);
    const parsedBak = JSON.parse(bakAfter.toString('utf8'));
    expect(parsedBak.repos[0].repoName).toBe('repo-s0');
    expect(parsedBak.formatVersion).toBe(1);
  });

  // E5: clear() persists empty snapshot and backup holds pre-clear state
  it('E5: clear() persists empty snapshot, backup holds pre-clear state; 2nd persist replaces backup', () => {
    const store = new FleetStore({ storageFile: primaryDb });
    store.ingest(makePayload('repo-pre-clear'));

    const preClearPrimary = fs.readFileSync(primaryDb);

    // Clear store
    store.clear();

    // Primary is empty snapshot
    expect(store.getRepos().length).toBe(0);
    const clearPrimary = fs.readFileSync(primaryDb);
    const parsedClear = JSON.parse(clearPrimary.toString('utf8'));
    expect(parsedClear.repos).toEqual([]);

    // Backup holds pre-clear state
    const bakAfterClear = fs.readFileSync(bakDb);
    expect(Buffer.compare(bakAfterClear, preClearPrimary)).toBe(0);

    // Second persist after clear replaces backup with the empty state (documented single generation)
    store.ingest(makePayload('repo-post-clear'));
    const bakAfterSecond = fs.readFileSync(bakDb);
    expect(Buffer.compare(bakAfterSecond, clearPrimary)).toBe(0);
  });

  // E6: Atomic rotation guarantees
  it('E6: rotation leaves no truncated .bak files when primary is absent or intact', () => {
    const store = new FleetStore({ storageFile: primaryDb });
    store.ingest(makePayload('repo-atomic-1'));
    store.ingest(makePayload('repo-atomic-2'));

    // Verify .bak exists and is completely valid JSON
    expect(fs.existsSync(bakDb)).toBe(true);
    const bakBytes = fs.readFileSync(bakDb);
    const parsed = JSON.parse(bakBytes.toString('utf8'));
    expect(parsed.formatVersion).toBe(1);
    expect(parsed.repos.length).toBe(1);
  });
});
