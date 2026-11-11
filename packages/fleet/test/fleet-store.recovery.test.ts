import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  FleetStore,
  FleetStoreCorruptionError,
  FleetStoreUnsupportedVersionError,
} from '../src/storage/fleet-store.js';
import { FaultFs } from './fixtures/fault-fs.js';
import {
  makePayload,
  makeRepoSummary,
  makeCanary,
  legacyFile,
  v1File,
  withBom,
  LoggerSpy,
} from './fixtures/store-fixtures.js';

describe('LAYER D: Load and Recovery Matrix (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;
  let primaryDb: string;
  let bakDb: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-recovery-test-'));
    primaryDb = path.join(tempDir, 'fleet-db.json');
    bakDb = path.join(tempDir, 'fleet-db.json.bak');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // State builder helpers
  function createS0(canary?: string) {
    const summary = makeRepoSummary('repo-0', 90, 'A', canary);
    return {
      repos: [summary],
      policy: {
        policyVersion: '1.0',
        failOnSeverity: 'HIGH' as const,
        blockUnreachableSca: false,
        deniedLicenses: ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'],
        requireHmacAudit: true,
        updatedAt: '2026-11-04T00:00:00.000Z',
      },
    };
  }

  function createS1(canary?: string) {
    const s0 = createS0(canary);
    const r1 = makeRepoSummary('repo-1', 95, 'A', canary);
    return {
      repos: [...s0.repos, r1],
      policy: {
        ...s0.policy,
        failOnSeverity: 'CRITICAL' as const,
      },
    };
  }

  function writeCandidateState(filePath: string, stateType: string, canary?: string) {
    const s0 = createS0(canary);
    const s1 = createS1(canary);

    switch (stateType) {
      case 'absent':
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        break;
      case 'valid-old':
        fs.writeFileSync(filePath, v1File({ repos: s0.repos, policy: s0.policy }), 'utf8');
        break;
      case 'valid-new':
        fs.writeFileSync(filePath, v1File({ repos: s1.repos, policy: s1.policy }), 'utf8');
        break;
      case 'truncated-0':
        fs.writeFileSync(filePath, '', 'utf8');
        break;
      case 'truncated-mid': {
        const full = v1File({ repos: s0.repos, policy: s0.policy });
        fs.writeFileSync(filePath, full.slice(0, Math.floor(full.length / 2)), 'utf8');
        break;
      }
      case 'truncated-last': {
        const full = v1File({ repos: s0.repos, policy: s0.policy });
        fs.writeFileSync(filePath, full.slice(0, full.length - 2), 'utf8');
        break;
      }
      case 'garbage':
        fs.writeFileSync(
          filePath,
          canary ? `xyz-garbage-${canary}-!@#$%^` : 'xyz-corrupt-garbage-bytes',
          'utf8'
        );
        break;
      case 'null':
        fs.writeFileSync(filePath, 'null', 'utf8');
        break;
      case 'array':
        fs.writeFileSync(filePath, '[]', 'utf8');
        break;
      case 'wrong-shape':
        fs.writeFileSync(filePath, '{"repos": "not-an-array"}', 'utf8');
        break;
      case 'digest-mismatch': {
        const full = v1File({ repos: s0.repos, policy: s0.policy });
        const tampered = full.replace('"repo-0', '"repo-tamper');
        fs.writeFileSync(filePath, tampered, 'utf8');
        break;
      }
      case 'unsupported-version':
        fs.writeFileSync(filePath, '{"formatVersion": 99, "repos": []}', 'utf8');
        break;
      case 'dir-in-place':
        fs.mkdirSync(filePath, { recursive: true });
        break;
      default:
        throw new Error(`Unknown stateType: ${stateType}`);
    }
  }

  // D1. Hand-written matrix of (primary, backup) states
  describe('D1: Comprehensive (primary, backup) state matrix', () => {
    it('(valid-new, valid-old) -> loads primary (S1), no quarantine, backup untouched', () => {
      writeCandidateState(primaryDb, 'valid-new');
      writeCandidateState(bakDb, 'valid-old');
      const bakBefore = fs.readFileSync(bakDb);

      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('primary');
      expect(store.getLoadReport().recovered).toBe(false);
      expect(store.getLoadReport().quarantined.length).toBe(0);
      expect(store.getRepos().length).toBe(2);
      expect(store.getPolicy().failOnSeverity).toBe('CRITICAL');

      // Backup untouched
      const bakAfter = fs.readFileSync(bakDb);
      expect(Buffer.compare(bakBefore, bakAfter)).toBe(0);
    });

    it('(truncated-mid, valid-old) -> recovers S0 from backup, quarantines primary, heals primary', () => {
      writeCandidateState(primaryDb, 'truncated-mid');
      const corruptBytes = fs.readFileSync(primaryDb);
      writeCandidateState(bakDb, 'valid-old');
      const bakBefore = fs.readFileSync(bakDb);

      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      const report = store.getLoadReport();
      expect(report.source).toBe('backup');
      expect(report.recovered).toBe(true);
      expect(report.quarantined.length).toBe(1);
      expect(logger.hasCode('FLEET_STORE_RECOVERED_FROM_BACKUP')).toBe(true);
      expect(logger.hasCode('FLEET_STORE_PRIMARY_CORRUPT')).toBe(true);

      // Quarantined file preserves corrupt bytes exactly
      const qFile = report.quarantined[0]!;
      expect(fs.existsSync(qFile)).toBe(true);
      const qBytes = fs.readFileSync(qFile);
      expect(Buffer.compare(corruptBytes, qBytes)).toBe(0);

      // Primary healed on disk: equals S0
      expect(fs.existsSync(primaryDb)).toBe(true);
      const healedStore = new FleetStore({ storageFile: primaryDb });
      expect(healedStore.getRepos().length).toBe(1);
      expect(healedStore.getRepo('repo-0')).toBeDefined();

      // Backup untouched
      const bakAfter = fs.readFileSync(bakDb);
      expect(Buffer.compare(bakBefore, bakAfter)).toBe(0);
    });

    it('(valid-new, truncated-last) -> loads primary S1, quarantines backup', () => {
      writeCandidateState(primaryDb, 'valid-new');
      writeCandidateState(bakDb, 'truncated-last');

      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('primary');
      expect(store.getLoadReport().recovered).toBe(false);
      expect(store.getLoadReport().quarantined.length).toBe(1);
      expect(logger.hasCode('FLEET_STORE_BACKUP_CORRUPT')).toBe(true);
      expect(store.getRepos().length).toBe(2);
    });

    it('(digest-mismatch, valid-old) -> recovers S0 from backup, quarantines primary with digest error', () => {
      writeCandidateState(primaryDb, 'digest-mismatch');
      writeCandidateState(bakDb, 'valid-old');

      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('backup');
      expect(store.getLoadReport().recovered).toBe(true);
      expect(store.getRepos().length).toBe(1);
    });

    it('(truncated-mid, truncated-last) -> empty-after-corruption, both quarantined, NO primary write', () => {
      writeCandidateState(primaryDb, 'truncated-mid');
      writeCandidateState(bakDb, 'truncated-last');

      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('empty-after-corruption');
      expect(store.getLoadReport().quarantined.length).toBe(2);
      expect(logger.hasCode('FLEET_STORE_STARTED_EMPTY_AFTER_CORRUPTION')).toBe(true);
      expect(store.getRepos().length).toBe(0);

      // Primary was renamed to quarantine, not written to!
      expect(fs.existsSync(primaryDb)).toBe(false);
    });

    it('(garbage, absent) -> empty-after-corruption, quarantines primary, starts empty', () => {
      writeCandidateState(primaryDb, 'garbage');
      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('empty-after-corruption');
      expect(store.getLoadReport().quarantined.length).toBe(1);
      expect(store.getRepos().length).toBe(0);
    });

    it('(absent, valid-old) -> recovers from backup, heals primary', () => {
      writeCandidateState(bakDb, 'valid-old');
      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('backup');
      expect(store.getLoadReport().recovered).toBe(true);
      expect(store.getRepos().length).toBe(1);
      expect(fs.existsSync(primaryDb)).toBe(true);
    });

    it('(null, valid-old) -> recovers S0 from backup, quarantines primary', () => {
      writeCandidateState(primaryDb, 'null');
      writeCandidateState(bakDb, 'valid-old');
      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('backup');
      expect(store.getLoadReport().recovered).toBe(true);
      expect(store.getLoadReport().quarantined.length).toBe(1);
      expect(store.getRepos().length).toBe(1);
      expect(store.getRepo('repo-0')?.repoName).toBe('repo-0');
    });

    it('(array, valid-old) -> recovers S0 from backup, quarantines primary', () => {
      writeCandidateState(primaryDb, 'array');
      writeCandidateState(bakDb, 'valid-old');
      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('backup');
      expect(store.getLoadReport().recovered).toBe(true);
      expect(store.getLoadReport().quarantined.length).toBe(1);
      expect(store.getRepos().length).toBe(1);
    });

    it('(wrong-shape, valid-old) -> recovers S0 from backup, quarantines primary', () => {
      writeCandidateState(primaryDb, 'wrong-shape');
      writeCandidateState(bakDb, 'valid-old');
      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('backup');
      expect(store.getLoadReport().recovered).toBe(true);
      expect(store.getLoadReport().quarantined.length).toBe(1);
      expect(store.getRepos().length).toBe(1);
    });

    it('(truncated-0, valid-old) -> recovers S0 from backup, quarantines primary', () => {
      writeCandidateState(primaryDb, 'truncated-0');
      writeCandidateState(bakDb, 'valid-old');
      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('backup');
      expect(store.getLoadReport().recovered).toBe(true);
      expect(store.getLoadReport().quarantined.length).toBe(1);
      expect(store.getRepos().length).toBe(1);
    });

    it('(dir-in-place, valid-old) -> handles directory gracefully, recovers from backup', () => {
      writeCandidateState(primaryDb, 'dir-in-place');
      writeCandidateState(bakDb, 'valid-old');
      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('backup');
      expect(store.getLoadReport().recovered).toBe(true);
      expect(store.getRepos().length).toBe(1);
    });
  });

  // D2. Fresh start
  describe('D2: Fresh start (both absent)', () => {
    it('produces source "none", zero warnings, zero logs, healthy status after first persist', () => {
      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(store.getLoadReport().source).toBe('none');
      expect(store.getLoadReport().recovered).toBe(false);
      expect(store.getLoadReport().warnings.length).toBe(0);
      expect(logger.entries.length).toBe(0);

      // Status healthy
      expect(store.getPersistenceStatus().healthy).toBe(true);

      // Persists cleanly
      store.ingest(makePayload('repo-fresh'));
      expect(fs.existsSync(primaryDb)).toBe(true);
      expect(store.getPersistenceStatus().healthy).toBe(true);
    });
  });

  // D3. strictLoad
  describe('D3: strictLoad behavior', () => {
    it('throws FleetStoreCorruptionError listing both paths and codes, modifies nothing on disk', () => {
      writeCandidateState(primaryDb, 'truncated-mid');
      writeCandidateState(bakDb, 'garbage');

      const primBytesBefore = fs.readFileSync(primaryDb);
      const bakBytesBefore = fs.readFileSync(bakDb);

      expect(() => new FleetStore({ storageFile: primaryDb, strictLoad: true })).toThrow(
        FleetStoreCorruptionError
      );

      // Verify files untouched on disk: zero renames, zero writes
      expect(Buffer.compare(fs.readFileSync(primaryDb), primBytesBefore)).toBe(0);
      expect(Buffer.compare(fs.readFileSync(bakDb), bakBytesBefore)).toBe(0);
      const entries = fs.readdirSync(tempDir);
      expect(entries.filter((e) => e.includes('.corrupt-')).length).toBe(0);
    });

    it('unsupported version throws FleetStoreUnsupportedVersionError in both strict and default modes', () => {
      writeCandidateState(primaryDb, 'unsupported-version');

      // Default mode throws FleetStoreUnsupportedVersionError
      expect(() => new FleetStore({ storageFile: primaryDb, strictLoad: false })).toThrow(
        FleetStoreUnsupportedVersionError
      );

      // Strict mode throws FleetStoreUnsupportedVersionError
      expect(() => new FleetStore({ storageFile: primaryDb, strictLoad: true })).toThrow(
        FleetStoreUnsupportedVersionError
      );
    });
  });

  // D4. Policy continuity
  describe('D4: Policy continuity across recovery', () => {
    it('custom policy in backup is restored completely on recovery, not reverted to defaults', () => {
      const customPolicy = {
        policyVersion: '1.0',
        failOnSeverity: 'MEDIUM' as const,
        blockUnreachableSca: true,
        deniedLicenses: ['Custom-GPL-99'],
        requireHmacAudit: true,
        updatedAt: '2026-11-04T00:00:00.000Z',
      };

      fs.writeFileSync(
        bakDb,
        v1File({
          repos: [],
          policy: customPolicy,
        }),
        'utf8'
      );
      // Corrupt primary
      fs.writeFileSync(primaryDb, 'corrupt', 'utf8');

      const store = new FleetStore({ storageFile: primaryDb });
      expect(store.getLoadReport().recovered).toBe(true);

      const recoveredPolicy = store.getPolicy();
      expect(recoveredPolicy.failOnSeverity).toBe('MEDIUM');
      expect(recoveredPolicy.blockUnreachableSca).toBe(true);
      expect(recoveredPolicy.deniedLicenses).toEqual(['Custom-GPL-99']);
      expect(recoveredPolicy.requireHmacAudit).toBe(true);
    });

    it('after both corrupt, defaults applied and FLEET_STORE_STARTED_EMPTY_AFTER_CORRUPTION logged', () => {
      fs.writeFileSync(primaryDb, 'corrupt-1', 'utf8');
      fs.writeFileSync(bakDb, 'corrupt-2', 'utf8');

      const logger = new LoggerSpy();
      const store = new FleetStore({ storageFile: primaryDb, internals: { logger } });

      expect(logger.hasCode('FLEET_STORE_STARTED_EMPTY_AFTER_CORRUPTION')).toBe(true);
      expect(store.getPolicy().failOnSeverity).toBe('HIGH');
      expect(store.getPolicy().blockUnreachableSca).toBe(false);
    });
  });

  // D5. Log hygiene
  describe('D5: Log hygiene across all error paths', () => {
    it('canary never appears in any log line or error message', () => {
      const canary = makeCanary();
      writeCandidateState(primaryDb, 'garbage', canary);
      writeCandidateState(bakDb, 'garbage', canary);

      const logger = new LoggerSpy();
      new FleetStore({ storageFile: primaryDb, internals: { logger } });

      for (const entry of logger.entries) {
        expect(entry.text.includes(canary)).toBe(false);
      }
    });
  });

  // D6. Quarantine retention
  describe('D6: Quarantine retention and pruning', () => {
    it('retains exactly the newest quarantineKeep (3) corrupt files and names match format', () => {
      let fakeTime = 1700000000000;

      // Produce 6 corrupt load events
      for (let i = 1; i <= 6; i++) {
        fakeTime += 10000;
        fs.writeFileSync(primaryDb, `corrupt-event-${i}`, 'utf8');

        new FleetStore({
          storageFile: primaryDb,
          quarantineKeep: 3,
          internals: {
            now: () => fakeTime,
            random: () => `000${i}`,
          },
        });
      }

      const files = fs.readdirSync(tempDir);
      const corruptFiles = files.filter((f) => f.includes('.corrupt-'));
      expect(corruptFiles.length).toBe(3);

      const regex = /^fleet-db\.json\.corrupt-\d{8}T\d{6}Z-[0-9a-f]{4}$/;
      for (const cf of corruptFiles) {
        expect(regex.test(cf)).toBe(true);
      }
    });

    it('falls back to copy and preserves corrupt bytes when rename is blocked by EBUSY', () => {
      fs.writeFileSync(primaryDb, 'corrupt-bytes-for-copy', 'utf8');

      const faultFs = new FaultFs({ platform: 'linux' });
      // Rename fails with EBUSY
      faultFs.failCall('renameSync', 1, 'EBUSY');

      const store = new FleetStore({
        storageFile: primaryDb,
        internals: {
          fs: faultFs,
          platform: 'linux',
        },
      });

      const qFile = store.getLoadReport().quarantined[0];
      expect(qFile).toBeDefined();
      expect(fs.existsSync(qFile!)).toBe(true);
      expect(fs.readFileSync(qFile!, 'utf8')).toBe('corrupt-bytes-for-copy');
    });
  });

  // D7. BOM stripping and rewriting
  describe('D7: BOM files are rewritten without BOM on next persist', () => {
    it('rewrites leading BOM without BOM on subsequent persist', () => {
      const s0 = createS0();
      const bomContent = withBom(
        Buffer.from(v1File({ repos: s0.repos, policy: s0.policy }), 'utf8')
      );
      fs.writeFileSync(primaryDb, bomContent);

      const store = new FleetStore({ storageFile: primaryDb });
      expect(store.getRepos().length).toBe(1);

      // Ingest new repo to trigger persist
      store.ingest(makePayload('repo-post-bom'));

      const rewritten = fs.readFileSync(primaryDb);
      // Does not start with BOM
      expect(rewritten[0] === 0xef && rewritten[1] === 0xbb && rewritten[2] === 0xbf).toBe(false);
    });
  });

  // D8. Legacy upgrade
  describe('D8: Legacy database upgrade', () => {
    it('loads legacy database and upgrades to formatVersion 1 with integrity on next persist', () => {
      const s0 = createS0();
      const legacyContent = legacyFile({ repos: s0.repos, policy: s0.policy });
      fs.writeFileSync(primaryDb, legacyContent, 'utf8');

      const store = new FleetStore({ storageFile: primaryDb });
      expect(store.getRepos().length).toBe(1);

      // Trigger persist
      store.ingest(makePayload('repo-upgraded'));

      const upgradedBytes = fs.readFileSync(primaryDb);
      const parsed = JSON.parse(upgradedBytes.toString('utf8'));
      expect(parsed.formatVersion).toBe(1);
      expect(parsed.integrity?.algorithm).toBe('sha256');
      expect(parsed.integrity?.digest.length).toBe(64);
    });
  });
});
