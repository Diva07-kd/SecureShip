import os from 'node:os';
import { describe, expect, it } from 'vitest';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import { detectMetadataAnomalies } from '../../src/supply-chain/detectors/metadata.detector.js';
import { SnapshotProvider } from '../../src/supply-chain/providers/snapshot.provider.js';
import { NullProvider } from '../../src/supply-chain/providers/null.provider.js';
import type { DetectorContext } from '../../src/supply-chain/internal/types.js';

describe('MetadataDetector (SC-META-*)', () => {
  const policy = SupplyChainPolicySchema.parse({
    privateScopes: ['@mycompany'],
  });

  const now = new Date('2026-10-21T00:00:00Z');
  const ctx: DetectorContext = {
    packageName: 'test-dep',
    version: '1.0.0',
    ecosystem: 'npm',
    packageDir: os.tmpdir(),
    now: () => now,
  };

  it('degrades gracefully with NullProvider without crashing', async () => {
    const hits = await detectMetadataAnomalies(
      'some-dep',
      '1.0.0',
      {},
      new NullProvider(),
      policy,
      ctx
    );
    expect(hits).toHaveLength(0);
  });

  it('detects dependency confusion for private scopes published to public registry (SC-META-002)', async () => {
    const snapshot = new SnapshotProvider();
    snapshot.setPackument('npm', '@mycompany/auth', {
      name: '@mycompany/auth',
      versions: { '1.0.0': { name: '@mycompany/auth', version: '1.0.0' } },
      time: { '1.0.0': '2026-10-01T00:00:00Z' },
      maintainers: [{ name: 'attacker' }],
    });

    const hits = await detectMetadataAnomalies('@mycompany/auth', '1.0.0', {}, snapshot, policy, {
      ...ctx,
      packageName: '@mycompany/auth',
    });

    expect(hits.some((h) => h.ruleId === 'SC-META-002')).toBe(true);
    const hit = hits.find((h) => h.ruleId === 'SC-META-002')!;
    expect(hit.severity).toBe('HIGH');
    expect(hit.blocking).toBe(true);
  });

  it('detects massive SemVer major version jump (SC-META-002)', async () => {
    const snapshot = new SnapshotProvider();
    snapshot.setPackument('npm', 'popular-tool', {
      name: 'popular-tool',
      versions: {
        '1.0.0': { name: 'popular-tool', version: '1.0.0' },
        '99.0.0': { name: 'popular-tool', version: '99.0.0' },
      },
      time: { '1.0.0': '2025-01-01T00:00:00Z', '99.0.0': '2026-10-10T00:00:00Z' },
      maintainers: [{ name: 'dev' }],
    });

    const hits = await detectMetadataAnomalies('popular-tool', '99.0.0', {}, snapshot, policy, {
      ...ctx,
      packageName: 'popular-tool',
      version: '99.0.0',
    });

    expect(hits.some((h) => h.ruleId === 'SC-META-002')).toBe(true);
  });

  it('detects chronological release timestamp anomaly in future (SC-META-001)', async () => {
    const snapshot = new SnapshotProvider();
    snapshot.setPackument('npm', 'chrono-pkg', {
      name: 'chrono-pkg',
      versions: { '1.0.0': { name: 'chrono-pkg', version: '1.0.0' } },
      // Timestamp set to 2029 (far in future relative to fixedNow 2026)
      time: { '1.0.0': '2029-01-01T00:00:00Z' },
      maintainers: [{ name: 'dev' }],
    });

    const hits = await detectMetadataAnomalies('chrono-pkg', '1.0.0', {}, snapshot, policy, {
      ...ctx,
      packageName: 'chrono-pkg',
    });

    expect(hits.some((h) => h.ruleId === 'SC-META-001')).toBe(true);
    const hit = hits.find((h) => h.ruleId === 'SC-META-001')!;
    expect(hit.severity).toBe('MEDIUM');
  });

  it('detects manifest desynchronization with hidden local install script (SC-META-003)', async () => {
    const snapshot = new SnapshotProvider();
    snapshot.setPackument('npm', 'desync-pkg', {
      name: 'desync-pkg',
      versions: {
        '1.0.0': {
          name: 'desync-pkg',
          version: '1.0.0',
          scripts: { test: 'vitest' }, // registry says only test script
        },
      },
      time: { '1.0.0': '2026-01-01T00:00:00Z' },
      maintainers: [{ name: 'dev' }],
    });

    // Local package.json contains a hidden postinstall script not on registry
    const localPkgJson = {
      name: 'desync-pkg',
      version: '1.0.0',
      scripts: {
        test: 'vitest',
        postinstall: 'node setup.js',
      },
    };

    const hits = await detectMetadataAnomalies(
      'desync-pkg',
      '1.0.0',
      localPkgJson,
      snapshot,
      policy,
      { ...ctx, packageName: 'desync-pkg' }
    );

    expect(hits.some((h) => h.ruleId === 'SC-META-003')).toBe(true);
    const hit = hits.find((h) => h.ruleId === 'SC-META-003')!;
    expect(hit.severity).toBe('HIGH');
    expect(hit.blocking).toBe(true);
  });
});
