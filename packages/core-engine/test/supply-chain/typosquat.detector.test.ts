import os from 'node:os';
import { describe, expect, it } from 'vitest';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import {
  damerauLevenshtein,
  detectTyposquats,
  PopularListIndex,
} from '../../src/supply-chain/detectors/typosquat.detector.js';
import { SnapshotProvider } from '../../src/supply-chain/providers/snapshot.provider.js';
import { NullProvider } from '../../src/supply-chain/providers/null.provider.js';
import type { DetectorContext } from '../../src/supply-chain/internal/types.js';

describe('TyposquatDetector (SC-TYPO-*, SC-HALL-*)', () => {
  const policy = SupplyChainPolicySchema.parse({});
  const fixedNow = new Date('2026-10-21T00:00:00Z');
  const ctx: DetectorContext = {
    packageName: 'test',
    version: '1.0.0',
    ecosystem: 'npm',
    packageDir: os.tmpdir(),
    now: () => fixedNow,
  };

  describe('damerauLevenshtein algorithm', () => {
    it('satisfies identity property D(a, a) = 0', () => {
      expect(damerauLevenshtein('express', 'express')).toBe(0);
      expect(damerauLevenshtein('', '')).toBe(0);
    });

    it('satisfies symmetry property D(a, b) = D(b, a)', () => {
      expect(damerauLevenshtein('lodash', 'lodsh')).toBe(damerauLevenshtein('lodsh', 'lodash'));
      expect(damerauLevenshtein('react', 'vue')).toBe(damerauLevenshtein('vue', 'react'));
    });

    it('handles adjacent transposition in distance 1', () => {
      expect(damerauLevenshtein('react', 'raect')).toBe(1);
      expect(damerauLevenshtein('lodash', 'loadsh')).toBe(1);
    });

    it('handles insertions and deletions in distance 1', () => {
      expect(damerauLevenshtein('express', 'exprss')).toBe(1); // deletion
      expect(damerauLevenshtein('express', 'expresss')).toBe(1); // insertion
    });

    it('supports maxDist early-exit', () => {
      const dist = damerauLevenshtein('completelydifferent', 'unrelated', 2);
      expect(dist).toBeGreaterThan(2);
    });

    it('handles empty string boundaries', () => {
      expect(damerauLevenshtein('', 'abc')).toBe(3);
      expect(damerauLevenshtein('abc', '')).toBe(3);
    });
  });

  describe('PopularListIndex', () => {
    const seed = [
      { name: 'express' },
      { name: 'react' },
      { name: 'lodash' },
      { name: 'cross-env' },
    ];
    const index = new PopularListIndex(seed);

    it('identifies exact matches', () => {
      expect(index.has('express')).toBe(true);
      expect(index.has('EXPRESS')).toBe(true);
      expect(index.has('unknown-pkg')).toBe(false);
    });

    it('retrieves candidates within length delta 2', () => {
      // 'exprss' has length 6 -> candidates of len 4..8 (includes 'express': 7, 'lodash': 6, 'react': 5)
      const candidates = index.getCandidates('exprss');
      expect(candidates).toContain('express');
      expect(candidates).toContain('lodash');
      expect(candidates).toContain('react');
    });
  });

  describe('detectTyposquats rules', () => {
    const seed = [
      { name: 'express' },
      { name: 'react' },
      { name: 'lodash' },
      { name: 'cross-env' },
      { name: 'date-fns' },
    ];
    const index = new PopularListIndex(seed);
    const nullProvider = new NullProvider();

    it('returns 0 hits for legitimate popular package itself', async () => {
      const hits = await detectTyposquats('express', 'npm', index, policy, nullProvider, {
        ...ctx,
        packageName: 'express',
      });
      expect(hits).toHaveLength(0);
    });

    it('detects edit distance typosquat (SC-TYPO-001)', async () => {
      // 'exprss' vs 'express': dist 1, max len 7, score 6/7 = 0.857 >= 0.82
      const hits = await detectTyposquats('exprss', 'npm', index, policy, nullProvider, {
        ...ctx,
        packageName: 'exprss',
      });

      expect(hits.some((h) => h.ruleId === 'SC-TYPO-001')).toBe(true);
      const hit = hits.find((h) => h.ruleId === 'SC-TYPO-001')!;
      expect(hit.severity).toBe('HIGH');
    });

    it('detects combosquatting suffix inflation (SC-TYPO-002)', async () => {
      const hits = await detectTyposquats('express-js', 'npm', index, policy, nullProvider, {
        ...ctx,
        packageName: 'express-js',
      });

      expect(hits.some((h) => h.ruleId === 'SC-TYPO-002')).toBe(true);
      const hit = hits.find((h) => h.ruleId === 'SC-TYPO-002')!;
      expect(hit.severity).toBe('MEDIUM');
    });

    it('detects scope confusion (SC-TYPO-002)', async () => {
      const hits = await detectTyposquats('@evil/react', 'npm', index, policy, nullProvider, {
        ...ctx,
        packageName: '@evil/react',
      });

      expect(hits.some((h) => h.ruleId === 'SC-TYPO-002')).toBe(true);
    });

    it('detects separator collapse squatting (SC-TYPO-003)', async () => {
      const hits = await detectTyposquats('crossenv', 'npm', index, policy, nullProvider, {
        ...ctx,
        packageName: 'crossenv',
      });

      expect(hits.some((h) => h.ruleId === 'SC-TYPO-003')).toBe(true);
      const hit = hits.find((h) => h.ruleId === 'SC-TYPO-003')!;
      expect(hit.severity).toBe('MEDIUM');
    });

    it('detects AI hallucination target vulnerability (SC-HALL-001)', async () => {
      const snapshot = new SnapshotProvider();
      snapshot.setPackument('npm', 'brand-new-fake-dep', {
        name: 'brand-new-fake-dep',
        versions: { '1.0.0': { name: 'brand-new-fake-dep', version: '1.0.0' } },
        time: { created: '2026-10-15T00:00:00Z', '1.0.0': '2026-10-15T00:00:00Z' },
        maintainers: [{ name: 'hallucinator' }],
      });
      snapshot.setWeeklyDownloads('npm', 'brand-new-fake-dep', 5);

      const hits = await detectTyposquats('brand-new-fake-dep', 'npm', index, policy, snapshot, {
        ...ctx,
        packageName: 'brand-new-fake-dep',
      });

      expect(hits.some((h) => h.ruleId === 'SC-HALL-001')).toBe(true);
      const hit = hits.find((h) => h.ruleId === 'SC-HALL-001')!;
      expect(hit.severity).toBe('HIGH');
    });
  });
});
