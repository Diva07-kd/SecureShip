import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { ScanOrchestrator } from '../src/orchestrator/scan-orchestrator.js';
import type {
  IScannerAdapter,
  ScanExecutionResult,
  ScanOptions,
  NormalizedFinding,
} from '@secureship/contracts';
import { MonorepoFixture } from './fixtures/monorepo.js';

describe('Layer F - ScanOrchestrator Hand-off & Subdirectory Diff Integration', () => {
  let fixture: MonorepoFixture;
  let nonExistentLicense: string;

  beforeEach(() => {
    fixture = MonorepoFixture.create();
    nonExistentLicense = path.join(os.tmpdir(), `nonexistent-license-${Date.now()}.json`);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    fixture.cleanup();
  });

  function createRecordingFakeAdapter(findingsToReturn: NormalizedFinding[] = []): {
    adapter: IScannerAdapter;
    getRecordedOptions: () => ScanOptions | undefined;
    getRecordedTargetDir: () => string | undefined;
  } {
    let recordedOptions: ScanOptions | undefined;
    let recordedTargetDir: string | undefined;

    const adapter: IScannerAdapter = {
      name: 'opengrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async (targetDir: string, options: ScanOptions = {}): Promise<ScanExecutionResult> => {
        recordedTargetDir = targetDir;
        recordedOptions = options;
        return {
          scannerName: 'opengrep',
          status: 'SUCCESS',
          findings: findingsToReturn,
          durationMs: 15,
          exitCode: 0,
          timedOut: false,
        };
      },
    };

    return {
      adapter,
      getRecordedOptions: () => recordedOptions,
      getRecordedTargetDir: () => recordedTargetDir,
    };
  }

  function makeFinding(
    filePath: string,
    startLine: number,
    endLine: number,
    id: string
  ): NormalizedFinding {
    return {
      id,
      fingerprint: id.padEnd(64, '0'),
      ruleId: 'r-opengrep-test',
      scannerName: 'opengrep',
      category: 'SAST',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: { filePath, startLine, endLine },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: `Finding ${id}`,
      description: `Description for ${id}`,
      cweIds: ['CWE-89'],
      evidence: [
        { scannerName: 'opengrep', scannerRuleId: 'r-opengrep-test', message: 'SQL injection' },
      ],
      createdAt: new Date().toISOString(),
    };
  }

  // F1. The scan resolves for a subdirectory target and report.mode is 'DIFF'
  it('F1: scan resolves for subdirectory target and reports mode DIFF', async () => {
    fixture.modifyFile('packages/core-engine/src/index.ts', 'export const orchMod = 1;\n');
    fixture.stage('packages/core-engine/src/index.ts');

    const fake = createRecordingFakeAdapter();

    const report = await ScanOrchestrator.scan({
      targetDir: fixture.coreEngineDir,
      staged: true,
      adapters: [fake.adapter],
      gate2Mode: 'off',
      licensePath: nonExistentLicense,
      offline: true,
    });

    expect(report.mode).toBe('DIFF');
    expect(report.target).toBe(fixture.coreEngineDir);
  });

  // F2. Adapter receives sorted target-relative list without prefixes, duplicates, or sibling leaks
  it('F2: adapter receives sorted target-relative list without prefixes or sibling leaks', async () => {
    // 1. Stage changes in core-engine
    fixture.modifyFile('packages/core-engine/src/index.ts', 'export const orchMod = 2;\n');
    fixture.stage('packages/core-engine/src/index.ts');

    // 2. Also stage changes in sibling packages/cli/src/index.ts and root docs/readme.md
    fixture.modifyFile('packages/cli/src/index.ts', 'export const cliIndexMod = 2;\n');
    fixture.modifyFile('docs/readme.md', '# Root doc change\n');
    fixture.stage(['packages/cli/src/index.ts', 'docs/readme.md']);

    const fake = createRecordingFakeAdapter();

    await ScanOrchestrator.scan({
      targetDir: fixture.coreEngineDir,
      staged: true,
      adapters: [fake.adapter],
      gate2Mode: 'off',
      licensePath: nonExistentLicense,
      offline: true,
    });

    const recorded = fake.getRecordedOptions();
    expect(recorded).toBeDefined();

    // Changed files passed to adapter must equal sorted target-relative list: ['src/index.ts']
    expect(recorded?.changedFiles).toEqual(['src/index.ts']);

    // Root target check
    const rootFake = createRecordingFakeAdapter();
    await ScanOrchestrator.scan({
      targetDir: fixture.repoRoot,
      staged: true,
      adapters: [rootFake.adapter],
      gate2Mode: 'off',
      licensePath: nonExistentLicense,
      offline: true,
    });

    const rootRecorded = rootFake.getRecordedOptions();
    expect(rootRecorded?.changedFiles).toEqual([
      'docs/readme.md',
      'packages/cli/src/index.ts',
      'packages/core-engine/src/index.ts',
    ]);
  });

  // F3. Findings filtering: in-scope vs out-of-scope routing
  it('F3: filters target-relative findings and reports exact in-scope count and totalOutOfScope count', async () => {
    // Modify lines 3-4 of packages/core-engine/src/index.ts
    fixture.modifyLines('packages/core-engine/src/index.ts', 3, 4, [
      'export const line3 = 300;',
      'export const line4 = 400;',
    ]);
    fixture.stage('packages/core-engine/src/index.ts');

    // Also modify sibling's src/main.ts
    fixture.modifyFile('packages/cli/src/main.ts', 'export const cliMainMod = true;\n');
    fixture.stage('packages/cli/src/main.ts');

    // Construct 4 findings:
    // 1. in changed hunk (line 3) -> IN SCOPE
    const f1InHunk = makeFinding('src/index.ts', 3, 3, 'f-in-hunk');
    // 2. in changed file outside hunk (line 1) -> OUT OF SCOPE when diffLines is active
    const f2OutsideHunk = makeFinding('src/index.ts', 1, 1, 'f-outside-hunk');
    // 3. in unchanged file in target (src/util.ts) -> OUT OF SCOPE
    const f3Unchanged = makeFinding('src/util.ts', 1, 1, 'f-unchanged');
    // 4. collides by relative name with sibling's changed file (src/main.ts) where core-engine has no main.ts -> OUT OF SCOPE
    const f4SiblingCollision = makeFinding('src/main.ts', 1, 1, 'f-sibling-collision');

    const fake = createRecordingFakeAdapter([
      f1InHunk,
      f2OutsideHunk,
      f3Unchanged,
      f4SiblingCollision,
    ]);

    const report = await ScanOrchestrator.scan({
      targetDir: fixture.coreEngineDir,
      staged: true,
      diffLines: true,
      adapters: [fake.adapter],
      gate2Mode: 'off',
      licensePath: nonExistentLicense,
      offline: true,
    });

    // Exactly 1 finding is in scope (f1InHunk)
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.id).toBe('f-in-hunk');

    // Exactly 3 findings are out of scope
    expect(report.summary.totalOutOfScope).toBe(3);
    expect(report.summary.totalReported).toBe(1);
    expect(report.summary.totalRaw).toBe(4);
  });

  // F4. A non-git target makes scan() reject with the exact I2 message
  it('F4: scan rejects non-git directory with exact byte-exact I2 message', async () => {
    const nonGitDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-orch-nongit-'));
    try {
      let cur = nonGitDir;
      let hasGit = false;
      while (true) {
        if (fs.existsSync(path.join(cur, '.git'))) {
          hasGit = true;
          break;
        }
        const parent = path.dirname(cur);
        if (parent === cur) break;
        cur = parent;
      }

      if (hasGit) {
        console.log('git suite skipped: temp dir has git ancestor in environment');
        return;
      }

      const fake = createRecordingFakeAdapter();

      await expect(
        ScanOrchestrator.scan({
          targetDir: nonGitDir,
          staged: true,
          adapters: [fake.adapter],
          gate2Mode: 'off',
          licensePath: nonExistentLicense,
          offline: true,
        })
      ).rejects.toThrow(
        `Directory '${nonGitDir}' is not a git repository. Incremental scan requires an initialized git repository.`
      );
    } finally {
      try {
        fs.rmSync(nonGitDir, { recursive: true, force: true });
      } catch {}
    }
  });

  // Layer G: CLI Replay
  describe('Layer G - CLI Replay (G1)', () => {
    it('G1: CLI replay in monorepo resolves subdirectory target with mode DIFF without crashing', () => {
      const cliDist = path.resolve(process.cwd(), '..', 'cli', 'dist', 'index.js');
      const resolvedDist = fs.existsSync(cliDist)
        ? cliDist
        : path.resolve(process.cwd(), 'packages', 'cli', 'dist', 'index.js');

      if (!fs.existsSync(resolvedDist)) {
        console.log(`git suite skipped: CLI binary ${resolvedDist} does not exist.`);
        return;
      }

      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const cliReplayVal = 99;\n');
      fixture.stage('packages/core-engine/src/index.ts');

      // 1. Run from repo root: scan packages/core-engine --staged --json
      const rootRes = spawnSync(
        process.execPath,
        [resolvedDist, 'scan', 'packages/core-engine', '--staged', '--json'],
        {
          cwd: fixture.repoRoot,
          encoding: 'utf-8',
        }
      );
      expect([0, 3]).toContain(rootRes.status);
      expect(rootRes.stderr.includes('not a git repository')).toBe(false);
      const rootJson = JSON.parse(rootRes.stdout);
      expect(rootJson.mode).toBe('DIFF');

      // 2. Run from inside package: scan . --staged --json
      const subRes = spawnSync(
        process.execPath,
        [resolvedDist, 'scan', '.', '--staged', '--json'],
        {
          cwd: fixture.coreEngineDir,
          encoding: 'utf-8',
        }
      );
      expect([0, 3]).toContain(subRes.status);
      expect(subRes.stderr.includes('not a git repository')).toBe(false);
      const subJson = JSON.parse(subRes.stdout);
      expect(subJson.mode).toBe('DIFF');
    }, 45_000);
  });
});
