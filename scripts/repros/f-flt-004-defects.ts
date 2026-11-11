/**
 * Reproduction scripts and benchmarks for F-FLT-004 Defect Reports
 * 1. Multi-writer lost update
 * 2. Event-loop blocking (> 50ms on 1,000 repos)
 * 3. Memory exposure (mutable references returned by getPolicy / getRepos)
 * 4. Other writer reconnaissance
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { performance } from 'node:perf_hooks';
import { FleetStore } from '../../packages/fleet/dist/storage/fleet-store.js';
import type { FleetIngestPayload } from '@secureship/contracts';

function makePayload(repoName: string, nComponents = 2): FleetIngestPayload {
  return {
    fleetToken: 'corp-valid-test-token-at-least-24-chars',
    repoName,
    branch: 'main',
    commitSha: 'a1b2c3d4e5f678901234567890abcdef12345678',
    scannedAt: '2026-11-04T00:00:00.000Z',
    durationMs: 150,
    summary: {
      totalRaw: 10,
      totalReported: 2,
      totalSuppressed: 8,
      bySeverity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { SAST: 1, SCA: 1, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      reachabilitySuppressionPct: 80,
    },
    vulnerabilities: [],
    sbom: {
      totalComponents: nComponents,
      compliantCount: nComponents,
      nonCompliantCount: 0,
      components: [],
    },
  };
}

export function reproDefect1MultiWriter(): { lostUpdateDetected: boolean; missingRepo: string } {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-defect1-'));
  const storageFile = path.join(tempDir, 'fleet-db.json');

  try {
    const storeA = new FleetStore({ storageFile });
    const storeB = new FleetStore({ storageFile });

    storeA.ingest(makePayload('repo-from-store-A'));
    storeB.ingest(makePayload('repo-from-store-B'));

    // Check what is on disk by opening a new reader
    const storeReader = new FleetStore({ storageFile });
    const reposOnDisk = storeReader.getRepos().map((r) => r.repoName);

    const hasRepoA = reposOnDisk.includes('repo-from-store-A');
    const hasRepoB = reposOnDisk.includes('repo-from-store-B');

    return {
      lostUpdateDetected: !hasRepoA && hasRepoB,
      missingRepo: !hasRepoA ? 'repo-from-store-A' : 'none',
    };
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
}

function makePayloadWithComponents(repoName: string, nComponents: number): FleetIngestPayload {
  const components = Array.from({ length: nComponents }, (_, i) => ({
    name: `lib-${i}`,
    version: `1.0.${i}`,
    ecosystem: 'npm',
    compliant: true,
    license: 'MIT',
  }));

  return {
    fleetToken: 'corp-valid-test-token-at-least-24-chars',
    repoName,
    branch: 'main',
    commitSha: 'a1b2c3d4e5f678901234567890abcdef12345678',
    scannedAt: '2026-11-04T00:00:00.000Z',
    durationMs: 150,
    summary: {
      totalRaw: 10,
      totalReported: 2,
      totalSuppressed: 8,
      bySeverity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { SAST: 1, SCA: 1, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      reachabilitySuppressionPct: 80,
    },
    vulnerabilities: [],
    sbom: {
      totalComponents: nComponents,
      compliantCount: nComponents,
      nonCompliantCount: 0,
      components,
    },
  };
}

export function benchmarkDefect2EventLoopBlocking(): Array<{
  repoCount: number;
  componentsPerRepo: number;
  fileSizeBytes: number;
  fileSizeFormatted: string;
  syncBlockDurationMs: number;
}> {
  const points = [50, 200, 1000];
  const results = [];

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-defect2-'));
  const storageFile = path.join(tempDir, 'fleet-db.json');

  try {
    const store = new FleetStore({ storageFile });

    for (const targetCount of points) {
      const currentCount = store.getRepos().length;
      // Ingest up to targetCount - 1
      for (let i = currentCount + 1; i < targetCount; i++) {
        store.ingest(makePayloadWithComponents(`repo-${i}`, 2000));
      }

      // Measure synchronous event-loop block time of the targetCount-th ingest
      const payload = makePayloadWithComponents(`repo-${targetCount}`, 2000);
      const t0 = performance.now();
      store.ingest(payload);
      const t1 = performance.now();

      const syncBlockDurationMs = Math.round((t1 - t0) * 100) / 100;
      const fileSizeBytes = fs.statSync(storageFile).size;
      const fileSizeFormatted = (fileSizeBytes / (1024 * 1024)).toFixed(2) + ' MB';

      results.push({
        repoCount: targetCount,
        componentsPerRepo: 2000,
        fileSizeBytes,
        fileSizeFormatted,
        syncBlockDurationMs,
      });
    }

    return results;
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
}

export function reproDefect3MemoryExposure(): {
  policyMutatedDirectly: boolean;
  repoMutatedDirectly: boolean;
} {
  const store = new FleetStore();
  store.ingest(makePayload('leak-repo'));

  // 1. Direct mutation of policy reference
  const policyRef = store.getPolicy();
  policyRef.failOnSeverity = 'LOW';
  const policyMutatedDirectly = store.getPolicy().failOnSeverity === 'LOW';

  // 2. Direct mutation of repo reference
  const repoList = store.getRepos();
  repoList[0]!.riskScore = 999;
  const repoMutatedDirectly = store.getRepo('leak-repo')?.riskScore === 999;

  return {
    policyMutatedDirectly,
    repoMutatedDirectly,
  };
}

async function run() {
  console.log('=== F-FLT-004 DEFECT REPRODUCTION RESULTS ===\n');

  console.log('1. Multi-Writer Lost Update:');
  const d1 = reproDefect1MultiWriter();
  console.log(JSON.stringify(d1, null, 2));

  console.log('\n2. Event-Loop Blocking Benchmark (1,000 Repos):');
  const d2 = benchmarkDefect2EventLoopBlocking();
  console.log(JSON.stringify(d2, null, 2));

  console.log('\n3. Memory Exposure / Mutable References:');
  const d3 = reproDefect3MemoryExposure();
  console.log(JSON.stringify(d3, null, 2));
}

run().catch(console.error);
