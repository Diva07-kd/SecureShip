import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { NullProvider } from '../../src/supply-chain/providers/null.provider.js';
import { SnapshotProvider } from '../../src/supply-chain/providers/snapshot.provider.js';
import { RegistryProvider } from '../../src/supply-chain/providers/registry.provider.js';
import type { DetectorContext } from '../../src/supply-chain/internal/types.js';

describe('Supply Chain Metadata Providers (WP3)', () => {
  const ctx: DetectorContext = {
    packageName: 'test-pkg',
    version: '1.0.0',
    ecosystem: 'npm',
    packageDir: os.tmpdir(),
    now: () => new Date('2026-10-21T00:00:00Z'),
  };

  describe('NullProvider', () => {
    const provider = new NullProvider();

    it('returns UNAVAILABLE error for all methods', async () => {
      const packumentRes = await provider.getPackument('npm', 'test-pkg', ctx);
      expect(packumentRes.ok).toBe(false);
      if (!packumentRes.ok) expect(packumentRes.error.code).toBe('UNAVAILABLE');

      const downloadsRes = await provider.getWeeklyDownloads('npm', 'test-pkg', ctx);
      expect(downloadsRes.ok).toBe(false);
      if (!downloadsRes.ok) expect(downloadsRes.error.code).toBe('UNAVAILABLE');

      const publisherRes = await provider.getPublisher('npm', 'test-pkg', '1.0.0', ctx);
      expect(publisherRes.ok).toBe(false);
      if (!publisherRes.ok) expect(publisherRes.error.code).toBe('UNAVAILABLE');

      const tarballRes = await provider.getTarball('npm', 'test-pkg', '1.0.0', ctx);
      expect(tarballRes.ok).toBe(false);
      if (!tarballRes.ok) expect(tarballRes.error.code).toBe('UNAVAILABLE');
    });
  });

  describe('SnapshotProvider', () => {
    it('serves in-memory configured responses', async () => {
      const snapshot = new SnapshotProvider();
      snapshot.setPackument('npm', 'my-pkg', {
        name: 'my-pkg',
        versions: {},
        time: {},
        maintainers: [{ name: 'alice', email: 'alice@example.com' }],
      });
      snapshot.setWeeklyDownloads('npm', 'my-pkg', 12345);
      snapshot.setTarball('npm', 'my-pkg', '1.0.0', new Uint8Array([1, 2, 3]));

      const pRes = await snapshot.getPackument('npm', 'my-pkg', ctx);
      expect(pRes.ok).toBe(true);
      if (pRes.ok) expect(pRes.value.maintainers[0]!.name).toBe('alice');

      const dRes = await snapshot.getWeeklyDownloads('npm', 'my-pkg', ctx);
      expect(dRes.ok).toBe(true);
      if (dRes.ok) expect(dRes.value).toBe(12345);

      const pubRes = await snapshot.getPublisher('npm', 'my-pkg', '1.0.0', ctx);
      expect(pubRes.ok).toBe(true);
      if (pubRes.ok) expect(pubRes.value?.username).toBe('alice');

      const tRes = await snapshot.getTarball('npm', 'my-pkg', '1.0.0', ctx);
      expect(tRes.ok).toBe(true);
      if (tRes.ok) expect(tRes.value).toHaveLength(3);
    });

    it('loads packument files from snapshot directory on disk', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-snap-'));
      try {
        const npmDir = path.join(tempDir, 'npm');
        fs.mkdirSync(npmDir, { recursive: true });

        const packumentData = {
          name: 'disk-pkg',
          versions: { '1.0.0': { name: 'disk-pkg', version: '1.0.0' } },
          time: { '1.0.0': '2026-01-01T00:00:00Z' },
          maintainers: [{ name: 'bob' }],
        };
        fs.writeFileSync(
          path.join(npmDir, 'disk-pkg.json'),
          JSON.stringify(packumentData),
          'utf-8'
        );

        const snapshot = new SnapshotProvider(tempDir);
        const res = await snapshot.getPackument('npm', 'disk-pkg', ctx);
        expect(res.ok).toBe(true);
        if (res.ok) expect(res.value.name).toBe('disk-pkg');

        // Missing package
        const missingRes = await snapshot.getPackument('npm', 'missing-pkg', ctx);
        expect(missingRes.ok).toBe(false);
        if (!missingRes.ok) expect(missingRes.error.code).toBe('NOT_FOUND');
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('handles corrupt JSON snapshot file gracefully', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-snap-err-'));
      try {
        const npmDir = path.join(tempDir, 'npm');
        fs.mkdirSync(npmDir, { recursive: true });
        fs.writeFileSync(path.join(npmDir, 'corrupt.json'), '{ invalid json ...', 'utf-8');

        const snapshot = new SnapshotProvider(tempDir);
        const res = await snapshot.getPackument('npm', 'corrupt', ctx);
        expect(res.ok).toBe(false);
        if (!res.ok) expect(res.error.code).toBe('INVALID_RESPONSE');
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('RegistryProvider', () => {
    it('returns UNAVAILABLE in offline phase execution', async () => {
      const registry = new RegistryProvider();
      const res = await registry.getPackument('npm', 'express', ctx);
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.error.code).toBe('UNAVAILABLE');

      const downRes = await registry.getWeeklyDownloads('npm', 'express', ctx);
      expect(downRes.ok).toBe(false);

      const pubRes = await registry.getPublisher('npm', 'express', '1.0.0', ctx);
      expect(pubRes.ok).toBe(false);

      const tarRes = await registry.getTarball('npm', 'express', '1.0.0', ctx);
      expect(tarRes.ok).toBe(false);
    });
  });
});
