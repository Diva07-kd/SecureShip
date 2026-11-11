import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  resolveDefaultRulePack,
  OpengrepAdapter,
  DEFAULT_OPENGREP_EXCLUDES,
} from '../../src/adapters/opengrep.adapter.js';
import { SafeProcessRunner } from '@secureship/core-engine';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sourceModuleDir = path.resolve(__dirname, '../../src/adapters');

describe('Layer C - Opengrep Rulepack Resolver & Scan Integration Suite (DEV-4 / F-PKG-001)', () => {
  const tempDirs: string[] = [];

  function makeTempDir(prefix: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  afterEach(() => {
    vi.restoreAllMocks();
    for (const d of tempDirs) {
      try {
        fs.rmSync(d, { recursive: true, force: true });
      } catch {
        // ignore cleanup error
      }
    }
    tempDirs.length = 0;
  });

  it('C1: explicit config.defaultRulePath wins unconditionally even when path does not exist', () => {
    const nonExistentPath = path.resolve('/path/that/does/not/exist/custom-rules.yml');
    const result = resolveDefaultRulePack({
      defaultRulePath: nonExistentPath,
    });

    expect(result).toEqual(nonExistentPath);
  });

  it('C2: table-driven priority: for each candidate 2-5, single existence wins, and candidate-k wins over candidate-(k+1)', () => {
    const fakeModuleDir = path.resolve('/fake/module/dir');
    const fakeCwd = path.resolve('/fake/cwd/dir');

    // Candidates in priority order:
    // Candidate 2 (idx 0): moduleDir/rules/secureship-sast
    // Candidate 3 (idx 1): moduleDir/../rules/secureship-sast
    // Candidate 4 (idx 2): moduleDir/../../rules/secureship-sast
    // Candidate 5 (idx 3): moduleDir/../../../../rules/secureship-sast
    const candidates = [
      path.resolve(fakeModuleDir, 'rules/secureship-sast'),
      path.resolve(fakeModuleDir, '../rules/secureship-sast'),
      path.resolve(fakeModuleDir, '../../rules/secureship-sast'),
      path.resolve(fakeModuleDir, '../../../../rules/secureship-sast'),
    ];

    // Sub-test A: For each candidate 2-5, when only that candidate exists -> it is chosen
    for (let i = 0; i < candidates.length; i++) {
      const activeCandidate = candidates[i]!;
      const exists = (p: string) => path.resolve(p) === activeCandidate;

      const resolved = resolveDefaultRulePack(
        {},
        {
          moduleDir: fakeModuleDir,
          cwd: fakeCwd,
          exists,
        }
      );

      expect(resolved).toEqual(activeCandidate);
    }

    // Sub-test B: For each adjacent pair (k and k+1), when both exist -> earlier (k) wins
    for (let i = 0; i < candidates.length - 1; i++) {
      const earlierCandidate = candidates[i]!;
      const laterCandidate = candidates[i + 1]!;
      const exists = (p: string) => {
        const norm = path.resolve(p);
        return norm === earlierCandidate || norm === laterCandidate;
      };

      const resolved = resolveDefaultRulePack(
        {},
        {
          moduleDir: fakeModuleDir,
          cwd: fakeCwd,
          exists,
        }
      );

      expect(resolved).toEqual(earlierCandidate);
    }
  });

  it('C3: total miss: when no candidate exists, returns legacy fallback path.resolve(cwd, "rules/secureship-sast")', () => {
    const fakeModuleDir = path.resolve('/empty/module/dir');
    const fakeCwd = path.resolve('/empty/cwd/dir');

    const expectedFallback = path.resolve(fakeCwd, 'rules/secureship-sast');

    const resolved = resolveDefaultRulePack(
      {},
      {
        moduleDir: fakeModuleDir,
        cwd: fakeCwd,
        exists: () => false,
      }
    );

    expect(resolved).toEqual(expectedFallback);
  });

  it('C4: scan() integration with SafeProcessRunner mocked: captures argv with --config, golden flags, and rulePaths precedence', async () => {
    const targetDir = makeTempDir('secureship-scan-target-');

    let capturedArgs: string[] = [];

    vi.spyOn(SafeProcessRunner, 'run').mockImplementation(async (_bin: string, args?: string[]) => {
      const actualArgs = args ?? [];
      capturedArgs = [...actualArgs];
      // Write a minimal valid SARIF report into the requested output file
      const sarifArg = actualArgs.find((a) => a.startsWith('--sarif-output=') || a === '--output');
      let outputPath = '';
      if (sarifArg?.startsWith('--sarif-output=')) {
        outputPath = sarifArg.replace('--sarif-output=', '');
      } else if (sarifArg === '--output') {
        const idx = actualArgs.indexOf('--output');
        outputPath = actualArgs[idx + 1] || '';
      }

      if (outputPath) {
        const minimalSarif = {
          version: '2.1.0',
          $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
          runs: [
            {
              tool: {
                driver: {
                  name: 'opengrep',
                  version: '1.31.0',
                  rules: [],
                },
              },
              results: [],
            },
          ],
        };
        fs.writeFileSync(outputPath, JSON.stringify(minimalSarif), 'utf-8');
      }

      return {
        exitCode: 0,
        stdout: '',
        stderr: '',
        timedOut: false,
        signal: null,
        durationMs: 10,
        truncated: false,
      };
    });

    const adapter = new OpengrepAdapter({
      binaryOverride: process.execPath,
    });

    // 1. When options.rulePaths is empty: resolved default pack must be present in --config
    const defaultPack = resolveDefaultRulePack({});
    const resDefault = await adapter.scan(targetDir, {});
    expect(resDefault.status).toEqual('SUCCESS');

    expect(capturedArgs).toContain('--config');
    const configIdx1 = capturedArgs.indexOf('--config');
    expect(capturedArgs[configIdx1 + 1]).toEqual(defaultPack);

    // Golden array validation for standard flags and excludes:
    const invariantFlags = capturedArgs.filter(
      (arg) => !arg.startsWith('--sarif-output=') && arg !== defaultPack && arg !== targetDir
    );
    const goldenFlags = [
      'scan',
      '--config',
      '--disable-version-check',
      '--use-git-ignore',
      ...DEFAULT_OPENGREP_EXCLUDES.map((pat) => `--exclude=${pat}`),
    ];
    expect(invariantFlags).toEqual(goldenFlags);

    // 2. When options.rulePaths is non-empty: custom rule path used; defaultPack MUST NOT be in argv
    const customRulePath = path.resolve('/custom/standalone-rule.yml');
    capturedArgs = [];
    const resCustom = await adapter.scan(targetDir, {
      rulePaths: [customRulePath],
    });
    expect(resCustom.status).toEqual('SUCCESS');

    expect(capturedArgs).toContain('--config');
    const configIdx2 = capturedArgs.indexOf('--config');
    expect(capturedArgs[configIdx2 + 1]).toEqual(customRulePath);
    expect(capturedArgs.includes(defaultPack)).toEqual(false);
  });

  it('C5: source-tree run: with cwd set to unrelated temp dir, real resolver still returns monorepo rules/secureship-sast with YAML files', () => {
    const unrelatedCwd = makeTempDir('secureship-unrelated-cwd-');

    const resolved = resolveDefaultRulePack(
      {},
      {
        moduleDir: sourceModuleDir,
        cwd: unrelatedCwd,
      }
    );

    // Must NOT resolve to the unrelated cwd fallback
    expect(resolved.startsWith(unrelatedCwd)).toEqual(false);

    // Must resolve to the repo's rules/secureship-sast directory
    expect(fs.existsSync(resolved)).toEqual(true);

    const yamlFiles = fs
      .readdirSync(resolved)
      .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
      .sort();

    expect(yamlFiles.length).toBeGreaterThanOrEqual(10);
    expect(yamlFiles).toContain('secureship-js-eval.yml');
    expect(yamlFiles).toContain('secureship-js-child-process-exec.yml');
  });
});
