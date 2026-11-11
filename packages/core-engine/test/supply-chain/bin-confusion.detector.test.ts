import os from 'node:os';
import { describe, expect, it } from 'vitest';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import { detectBinConfusion } from '../../src/supply-chain/detectors/bin-confusion.detector.js';
import type { DetectorContext } from '../../src/supply-chain/internal/types.js';

describe('BinConfusionDetector (SC-BIN-*)', () => {
  const policy = SupplyChainPolicySchema.parse({});
  const ctx: DetectorContext = {
    packageName: 'custom-tool',
    version: '1.0.0',
    ecosystem: 'npm',
    packageDir: os.tmpdir(),
    now: () => new Date('2026-10-21T00:00:00Z'),
  };

  it('reports zero hits when bin is not specified or clean', () => {
    expect(detectBinConfusion({}, policy, ctx)).toHaveLength(0);

    const cleanPkg = {
      name: 'custom-tool',
      bin: {
        'custom-tool': './bin/cli.js',
      },
    };
    expect(detectBinConfusion(cleanPkg, policy, ctx)).toHaveLength(0);
  });

  it('detects path traversal escaping package root in bin field (SC-BIN-001)', () => {
    const traversalCases = [
      '../outside.js',
      '../../root.js',
      '/usr/local/bin/evil',
      '..\\windows\\sys.js',
    ];

    for (const target of traversalCases) {
      const pkgJson = {
        name: 'custom-tool',
        bin: {
          runner: target,
        },
      };

      const hits = detectBinConfusion(pkgJson, policy, ctx);
      expect(hits.some((h) => h.ruleId === 'SC-BIN-001')).toBe(true);
      const hit = hits.find((h) => h.ruleId === 'SC-BIN-001')!;
      expect(hit.severity).toBe('HIGH');
      expect(hit.blocking).toBe(true);
    }
  });

  it('detects system command collisions in bin name (SC-BIN-002)', () => {
    const systemCommands = ['git', 'node', 'curl', 'ssh', 'bash', 'npm'];

    for (const cmd of systemCommands) {
      const pkgJson = {
        name: 'custom-tool',
        bin: {
          [cmd]: './bin/cli.js',
        },
      };

      const hits = detectBinConfusion(pkgJson, policy, ctx);
      expect(hits.some((h) => h.ruleId === 'SC-BIN-002')).toBe(true);
      const hit = hits.find((h) => h.ruleId === 'SC-BIN-002')!;
      expect(hit.severity).toBe('HIGH');
    }
  });

  it('handles string bin field correctly for scoped and unscoped packages', () => {
    const scopedCtx: DetectorContext = {
      ...ctx,
      packageName: '@evil/curl',
    };

    const pkgJson = {
      name: '@evil/curl',
      bin: './bin/curl.js',
    };

    const hits = detectBinConfusion(pkgJson, policy, scopedCtx);
    expect(hits.some((h) => h.ruleId === 'SC-BIN-002')).toBe(true);
  });
});
