import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  DbLocator,
  FreshnessEvaluator,
  assertOfflineAllowed,
  createOfflineContext,
  OfflineGenerationManifest,
} from '../src/offline/index.js';
import { ScanOrchestrator } from '../src/orchestrator/scan-orchestrator.js';
import { SarifExporter } from '../src/report/sarif-exporter.js';
import { IScannerAdapter, ScanExecutionResult, ScanOptions } from '@secureship/contracts';

class DummyOfflineAdapter implements IScannerAdapter {
  readonly name = 'trivy';
  readonly category = 'SCA' as const;
  readonly versionStr = '0.76.0';

  async isAvailable(): Promise<boolean> {
    return true;
  }

  supportsProject(): boolean {
    return true;
  }

  async version(): Promise<string> {
    return this.versionStr;
  }

  async scan(_targetDir: string, _options: ScanOptions = {}): Promise<ScanExecutionResult> {
    return {
      scannerName: this.name,
      status: 'SUCCESS',
      findings: [],
      durationMs: 5,
      exitCode: 0,
      timedOut: false,
    };
  }
}

describe('Offline Database Layer & Egress Guards (WP-C4)', () => {
  let tempDbDir: string;

  beforeEach(() => {
    tempDbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-offline-db-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDbDir)) {
      try {
        fs.rmSync(tempDbDir, { recursive: true, force: true });
      } catch {
        // Best effort
      }
    }
  });

  describe('DbLocator', () => {
    it('returns null when CURRENT pointer does not exist', () => {
      const current = DbLocator.getCurrentGenerationId(tempDbDir);
      expect(current).toBeNull();
      expect(DbLocator.hasValidGeneration(tempDbDir)).toBe(false);
      expect(DbLocator.getActiveGeneration(tempDbDir)).toBeNull();
    });

    it('returns null when CURRENT is empty or corrupt', () => {
      fs.writeFileSync(path.join(tempDbDir, 'CURRENT'), '   \n  ');
      expect(DbLocator.getCurrentGenerationId(tempDbDir)).toBeNull();
    });

    it('returns null when generation folder does not exist', () => {
      fs.writeFileSync(path.join(tempDbDir, 'CURRENT'), 'gen-missing');
      expect(DbLocator.getCurrentGenerationId(tempDbDir)).toBe('gen-missing');
      expect(DbLocator.hasValidGeneration(tempDbDir)).toBe(false);
      expect(DbLocator.getActiveGeneration(tempDbDir)).toBeNull();
    });

    it('returns null when generation manifest.json is invalid or missing', () => {
      const genDir = path.join(tempDbDir, 'generations', 'gen-1');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(tempDbDir, 'CURRENT'), 'gen-1');

      expect(DbLocator.loadGenerationManifest('gen-1', tempDbDir)).toBeNull();
      expect(DbLocator.hasValidGeneration(tempDbDir)).toBe(false);

      fs.writeFileSync(path.join(genDir, 'manifest.json'), '{ invalid json');
      expect(DbLocator.loadGenerationManifest('gen-1', tempDbDir)).toBeNull();
    });

    it('loads valid generation manifest and resolves tool cache directories', () => {
      const genId = 'gen-20261026-001';
      const genDir = path.join(tempDbDir, 'generations', genId);
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(tempDbDir, 'CURRENT'), genId);

      const manifest: OfflineGenerationManifest = {
        schemaVersion: 1,
        generationId: genId,
        createdAt: '2026-10-26T00:00:00.000Z',
        importedAt: '2026-10-26T01:00:00.000Z',
        trust: 'VERIFIED',
        components: [
          {
            id: 'trivy-db',
            kind: 'db',
            version: '2',
            upstreamUpdatedAt: '2026-10-25T12:00:00.000Z',
            totalSizeBytes: 1024,
            files: [
              {
                path: 'trivy/db/trivy.db',
                size: 1024,
                sha256: 'a'.repeat(64),
              },
            ],
          },
        ],
      };
      fs.writeFileSync(path.join(genDir, 'manifest.json'), JSON.stringify(manifest, null, 2));

      expect(DbLocator.hasValidGeneration(tempDbDir)).toBe(true);
      const active = DbLocator.getActiveGeneration(tempDbDir);
      expect(active).not.toBeNull();
      expect(active!.id).toBe(genId);
      expect(active!.manifest.generationId).toBe(genId);
      expect(DbLocator.getTrivyCacheDir(active!.dir)).toBe(path.join(genDir, 'trivy'));
      expect(DbLocator.getOsvDbDir(active!.dir)).toBe(path.join(genDir, 'osv'));
    });

    it('lists all generation directory names sorted', () => {
      const gensDir = path.join(tempDbDir, 'generations');
      fs.mkdirSync(path.join(gensDir, 'gen-2'), { recursive: true });
      fs.mkdirSync(path.join(gensDir, 'gen-1'), { recursive: true });
      fs.writeFileSync(path.join(gensDir, 'some-file.txt'), 'not a dir');

      const list = DbLocator.listGenerations(tempDbDir);
      expect(list).toEqual(['gen-1', 'gen-2']);
    });
  });

  describe('FreshnessEvaluator', () => {
    const fixedNow = new Date('2026-10-26T12:00:00.000Z');
    const evaluator = new FreshnessEvaluator(() => fixedNow);

    it('evaluates fresh generation (< 7 days)', () => {
      const manifest: OfflineGenerationManifest = {
        schemaVersion: 1,
        generationId: 'gen-fresh',
        createdAt: '2026-10-24T12:00:00.000Z',
        importedAt: '2026-10-24T12:00:00.000Z',
        trust: 'VERIFIED',
        components: [
          {
            id: 'trivy-db',
            kind: 'db',
            version: '2',
            upstreamUpdatedAt: '2026-10-24T12:00:00.000Z',
            totalSizeBytes: 100,
            files: [],
          },
        ],
      };

      const result = evaluator.evaluate(manifest);
      expect(result.status).toBe('FRESH');
      expect(result.isStale).toBe(false);
      expect(result.isExpired).toBe(false);
      expect(result.ageDays).toBe(2);
    });

    it('evaluates stale generation (> 7 days, <= 30 days)', () => {
      const manifest: OfflineGenerationManifest = {
        schemaVersion: 1,
        generationId: 'gen-stale',
        createdAt: '2026-10-15T12:00:00.000Z',
        importedAt: '2026-10-15T12:00:00.000Z',
        trust: 'VERIFIED',
        components: [
          {
            id: 'trivy-db',
            kind: 'db',
            version: '2',
            upstreamUpdatedAt: '2026-10-15T12:00:00.000Z',
            totalSizeBytes: 100,
            files: [],
          },
        ],
      };

      const result = evaluator.evaluate(manifest);
      expect(result.status).toBe('STALE');
      expect(result.isStale).toBe(true);
      expect(result.isExpired).toBe(false);
      expect(result.ageDays).toBe(11);
    });

    it('evaluates expired generation older than 30 days', () => {
      const manifest: OfflineGenerationManifest = {
        schemaVersion: 1,
        generationId: 'gen-expired',
        createdAt: '2026-09-01T12:00:00.000Z',
        importedAt: '2026-09-01T12:00:00.000Z',
        trust: 'UNSIGNED',
        components: [
          {
            id: 'trivy-db',
            kind: 'db',
            version: '2',
            upstreamUpdatedAt: '2026-09-01T12:00:00.000Z',
            totalSizeBytes: 100,
            files: [],
          },
        ],
      };

      const result = evaluator.evaluate(manifest);
      expect(result.status).toBe('EXPIRED');
      expect(result.isStale).toBe(true);
      expect(result.isExpired).toBe(true);
      expect(result.ageDays).toBeGreaterThan(30);
    });
  });

  describe('assertOfflineAllowed (Egress Guard)', () => {
    it('does nothing when isOffline is false', () => {
      expect(() => assertOfflineAllowed('fleet', false)).not.toThrow();
      expect(() => assertOfflineAllowed('cloud-ai', false)).not.toThrow();
      expect(() => assertOfflineAllowed('install-tools', false)).not.toThrow();
    });

    it('blocks fleet egress in offline mode', () => {
      expect(() => assertOfflineAllowed('fleet', true)).toThrow(
        /\[Security Violation\] Feature 'fleet' requires outbound network access/
      );
    });

    it('blocks cloud AI egress without loopback in offline mode', () => {
      expect(() => assertOfflineAllowed('cloud-ai', true)).toThrow(
        /\[Security Violation\] Feature 'cloud-ai' requires outbound network access/
      );
    });

    it('allows AI egress when pointing to local loopback (Ollama/local model)', () => {
      expect(() => assertOfflineAllowed('cloud-ai', true, { isLoopback: true })).not.toThrow();
    });

    it('blocks install-tools in offline mode', () => {
      expect(() => assertOfflineAllowed('install-tools', true)).toThrow(
        /\[Security Violation\] Feature 'install-tools' requires outbound network access/
      );
    });

    it('allows license-activation when isOfflineLicense is true', () => {
      expect(() =>
        assertOfflineAllowed('license-activation', true, { isOfflineLicense: true })
      ).not.toThrow();
    });
  });

  describe('createOfflineContext', () => {
    it('returns disabled context when offline is false', () => {
      const ctx = createOfflineContext({ offline: false });
      expect(ctx.enabled).toBe(false);
      expect(ctx.completeness).toBe('COMPLETE');
      expect(ctx.databases).toEqual([]);
    });

    it('throws error in strict mode when no offline database is installed', () => {
      expect(() => createOfflineContext({ offline: true, strict: true, dbDir: tempDbDir })).toThrow(
        /\[Offline Security Violation\] No offline vulnerability database installed/
      );
    });

    it('returns DEGRADED completeness in non-strict mode when no offline database is installed', () => {
      const ctx = createOfflineContext({ offline: true, strict: false, dbDir: tempDbDir });
      expect(ctx.enabled).toBe(true);
      expect(ctx.completeness).toBe('DEGRADED');
      expect(ctx.warnings.length).toBeGreaterThan(0);
      expect(ctx.warnings[0]).toContain('No offline vulnerability database installed');
    });

    it('returns COMPLETE context with fresh database generation', () => {
      const genId = 'gen-fresh-001';
      const genDir = path.join(tempDbDir, 'generations', genId);
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(tempDbDir, 'CURRENT'), genId);

      const manifest: OfflineGenerationManifest = {
        schemaVersion: 1,
        generationId: genId,
        createdAt: '2026-10-25T12:00:00.000Z',
        importedAt: '2026-10-25T12:00:00.000Z',
        trust: 'VERIFIED',
        components: [
          {
            id: 'trivy-db',
            kind: 'db',
            version: '2',
            upstreamUpdatedAt: '2026-10-25T12:00:00.000Z',
            totalSizeBytes: 500,
            files: [],
          },
          {
            id: 'osv-offline-db',
            kind: 'db',
            version: '2026.10.25',
            upstreamUpdatedAt: '2026-10-25T12:00:00.000Z',
            totalSizeBytes: 300,
            files: [],
          },
        ],
      };
      fs.writeFileSync(path.join(genDir, 'manifest.json'), JSON.stringify(manifest));

      const ctx = createOfflineContext({
        offline: true,
        strict: true,
        dbDir: tempDbDir,
        now: () => new Date('2026-10-26T12:00:00.000Z'),
      });

      expect(ctx.enabled).toBe(true);
      expect(ctx.completeness).toBe('COMPLETE');
      expect(ctx.generationId).toBe(genId);
      expect(ctx.databases).toHaveLength(2);
      expect(ctx.databases[0]?.id).toBe('trivy-db');
      expect(ctx.databases[0]?.trust).toBe('VERIFIED');
    });

    it('throws error in strict mode when database generation is expired (> 30 days)', () => {
      const genId = 'gen-expired-001';
      const genDir = path.join(tempDbDir, 'generations', genId);
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(tempDbDir, 'CURRENT'), genId);

      const manifest: OfflineGenerationManifest = {
        schemaVersion: 1,
        generationId: genId,
        createdAt: '2026-08-01T12:00:00.000Z',
        importedAt: '2026-08-01T12:00:00.000Z',
        trust: 'VERIFIED',
        components: [
          {
            id: 'trivy-db',
            kind: 'db',
            version: '2',
            upstreamUpdatedAt: '2026-08-01T12:00:00.000Z',
            totalSizeBytes: 500,
            files: [],
          },
        ],
      };
      fs.writeFileSync(path.join(genDir, 'manifest.json'), JSON.stringify(manifest));

      expect(() =>
        createOfflineContext({
          offline: true,
          strict: true,
          dbDir: tempDbDir,
          now: () => new Date('2026-10-26T12:00:00.000Z'),
        })
      ).toThrow(/Under --strict, scanning cannot proceed with an expired database/);
    });
  });

  describe('ScanOrchestrator & SARIF Offline Provenance Integration', () => {
    it('embeds offline provenance in ScanReport and SARIF run properties', async () => {
      const genId = 'gen-integ-001';
      const genDir = path.join(tempDbDir, 'generations', genId);
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(tempDbDir, 'CURRENT'), genId);

      const manifest: OfflineGenerationManifest = {
        schemaVersion: 1,
        generationId: genId,
        createdAt: '2026-10-25T12:00:00.000Z',
        importedAt: '2026-10-25T12:00:00.000Z',
        trust: 'VERIFIED',
        components: [
          {
            id: 'trivy-db',
            kind: 'db',
            version: '2',
            upstreamUpdatedAt: '2026-10-25T12:00:00.000Z',
            totalSizeBytes: 500,
            files: [],
          },
        ],
      };
      fs.writeFileSync(path.join(genDir, 'manifest.json'), JSON.stringify(manifest));

      const report = await ScanOrchestrator.scan({
        targetDir: tempDbDir,
        offline: true,
        dbDir: tempDbDir,
        adapters: [new DummyOfflineAdapter()],
      });

      expect(report.offline).toBeDefined();
      expect(report.offline!.enabled).toBe(true);
      expect(report.offline!.completeness).toBe('COMPLETE');
      expect(report.offline!.databases).toHaveLength(1);
      expect(report.offline!.databases[0]?.id).toBe('trivy-db');

      const sarif = SarifExporter.export(report);
      const parsedSarif = JSON.parse(sarif);
      expect(parsedSarif.runs[0].properties?.offline).toBeDefined();
      expect(parsedSarif.runs[0].properties.offline.enabled).toBe(true);
    });
  });
});
