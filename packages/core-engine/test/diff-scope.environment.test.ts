import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { DiffScope } from '../src/git/diff-scope.js';
import { DiffScope as DiffScopeBaseline } from './fixtures/diff-scope.baseline.js';
import { SafeProcessRunner } from '../src/sandbox/safe-process-runner.js';
import { MonorepoFixture } from './fixtures/monorepo.js';

describe('Layer E - Environment Determinism & Side Effect Isolation', () => {
  let fixture: MonorepoFixture;
  let hostileHome: string;
  let originalHome: string | undefined;
  let originalUserProfile: string | undefined;

  beforeEach(() => {
    fixture = MonorepoFixture.create();
    hostileHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-hostile-home-'));
    originalHome = process.env.HOME;
    originalUserProfile = process.env.USERPROFILE;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;

    if (originalUserProfile !== undefined) process.env.USERPROFILE = originalUserProfile;
    else delete process.env.USERPROFILE;

    try {
      fs.rmSync(hostileHome, { recursive: true, force: true });
    } catch {}

    fixture.cleanup();
  });

  // E0. Determine child environment and prove canary is live
  it('E0: canary proves hostile global gitconfig reaches child process via SafeProcessRunner', async () => {
    const gitconfigContent =
      [
        '[diff]',
        '  mnemonicPrefix = true',
        '  noprefix = true',
        '  relative = true',
        '  renames = copies',
        '[color]',
        '  ui = always',
        '  diff = always',
        '[core]',
        '  quotePath = true',
        '[status]',
        '  showUntrackedFiles = no',
      ].join('\n') + '\n';

    fs.writeFileSync(path.join(hostileHome, '.gitconfig'), gitconfigContent, 'utf-8');

    // Deliver hostile config through HOME and USERPROFILE allowlisted by SafeProcessRunner
    process.env.HOME = hostileHome;
    process.env.USERPROFILE = hostileHome;

    const canaryRun = await SafeProcessRunner.run('git', [
      'config',
      '--global',
      '--get',
      'diff.mnemonicPrefix',
    ]);
    expect(canaryRun.exitCode).toBe(0);
    expect(canaryRun.stdout.trim()).toBe('true');
  });

  // E1. Hostile global config vs clean environment
  it('E1: hostile gitconfig does not corrupt diffLines ranges or non-ASCII filenames on subdirectory target', async () => {
    // 1. Create a non-ASCII file in packages/core-engine/src/
    const unicodeRel = 'packages/core-engine/src/donnée.ts';
    const initialContent =
      [
        'export const line1 = "début";',
        'export const line2 = "deuxième";',
        'export const line3 = "troisième";',
        'export const line4 = "fin";',
      ].join('\n') + '\n';
    fixture.addFile(unicodeRel, initialContent);
    fixture.commitAll('Add non-ASCII file');

    // 2. Modify lines 2-3 in the file
    fixture.modifyLines(unicodeRel, 2, 3, [
      'export const line2 = "modifié_2";',
      'export const line3 = "modifié_3";',
    ]);
    fixture.stage(unicodeRel);

    // 3. Run in clean environment first to capture ground truth
    const cleanScope = await DiffScope.computeDiffScope(fixture.coreEngineDir, {
      staged: true,
      diffLines: true,
    });
    expect(cleanScope.isDiffMode).toBe(true);
    expect(cleanScope.targetRelativeFiles).toEqual(['src/donnée.ts']);
    expect(cleanScope.fileLineRanges.get('src/donnée.ts')).toEqual([{ startLine: 2, endLine: 3 }]);

    // 4. Set up hostile environment
    const hostileGitconfig =
      [
        '[diff]',
        '  mnemonicPrefix = true',
        '  noprefix = true',
        '  relative = true',
        '  renames = copies',
        '[color]',
        '  ui = always',
        '  diff = always',
        '[core]',
        '  quotePath = true',
        '[status]',
        '  showUntrackedFiles = no',
      ].join('\n') + '\n';
    fs.writeFileSync(path.join(hostileHome, '.gitconfig'), hostileGitconfig, 'utf-8');
    process.env.HOME = hostileHome;
    process.env.USERPROFILE = hostileHome;

    // 5. Run remediated DiffScope in hostile environment
    const hostileScope = await DiffScope.computeDiffScope(fixture.coreEngineDir, {
      staged: true,
      diffLines: true,
    });

    // Results must equal clean environment results exactly
    expect(hostileScope.isDiffMode).toBe(cleanScope.isDiffMode);
    expect(hostileScope.targetRelativeFiles).toEqual(cleanScope.targetRelativeFiles);
    expect(Array.from(hostileScope.changedFiles).sort()).toEqual(
      Array.from(cleanScope.changedFiles).sort()
    );
    expect(hostileScope.fileLineRanges.get('src/donnée.ts')).toEqual(
      cleanScope.fileLineRanges.get('src/donnée.ts')
    );

    // 6. Prove baseline failure:
    // On subdirectory target, baseline crashes with I2
    await expect(
      DiffScopeBaseline.computeDiffScope(fixture.coreEngineDir, {
        staged: true,
        diffLines: true,
      })
    ).rejects.toThrow(/is not a git repository/);

    // On root target, baseline fails to parse hunks under mnemonicPrefix / noprefix / quotePath
    const baselineRootScope = await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {
      staged: true,
      diffLines: true,
    });
    // Due to noprefix (no +++ b/ prefix) or quotePath (octal quoted), baseline cannot resolve ranges for the file
    const baselineRanges = baselineRootScope.fileLineRanges.get(unicodeRel);
    // Baseline either has no entry or fails to match the clean ranges:
    expect(baselineRanges === undefined || baselineRanges.length === 0).toBe(true);
  });

  // E2. External-diff and textconv canaries
  it('E2: external-diff and textconv canaries are never executed (--no-ext-diff and --no-textconv)', async () => {
    if (process.platform === 'win32') {
      console.log(
        'git suite skipped on win32: external diff script executable bits not supported on win32'
      );
      return;
    }

    const canaryExtFile = path.join(fixture.repoRoot, 'canary-ext-invoked.txt');
    const canaryTextconvFile = path.join(fixture.repoRoot, 'canary-textconv-invoked.txt');

    const extScript = path.join(fixture.repoRoot, 'ext-diff.sh');
    fs.writeFileSync(extScript, `#!/bin/sh\ntouch "${canaryExtFile}"\nexit 0\n`, { mode: 0o755 });

    const textconvScript = path.join(fixture.repoRoot, 'textconv.sh');
    fs.writeFileSync(textconvScript, `#!/bin/sh\ntouch "${canaryTextconvFile}"\ncat "$1"\n`, {
      mode: 0o755,
    });

    // Configure diff.external and textconv in repo config
    fixture.execGit(['config', 'diff.external', extScript]);
    fixture.execGit(['config', 'diff.customfilter.textconv', textconvScript]);
    fs.writeFileSync(
      path.join(fixture.repoRoot, '.gitattributes'),
      '*.ts diff=customfilter\n',
      'utf-8'
    );
    fixture.stage('.gitattributes');

    fixture.modifyLines('packages/core-engine/src/index.ts', 1, 2, [
      'export const ext1 = 1;',
      'export const ext2 = 2;',
    ]);
    fixture.stage('packages/core-engine/src/index.ts');

    // Run remediated scan
    await DiffScope.computeDiffScope(fixture.coreEngineDir, {
      staged: true,
      diffLines: true,
    });

    // Canary files must NOT exist under remediated DiffScope (--no-ext-diff and --no-textconv)
    expect(fs.existsSync(canaryExtFile)).toBe(false);
    expect(fs.existsSync(canaryTextconvFile)).toBe(false);

    // Red proof: baseline run on repo root triggers external-diff and textconv scripts
    await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {
      staged: true,
      diffLines: true,
    });
    expect(fs.existsSync(canaryExtFile) || fs.existsSync(canaryTextconvFile)).toBe(true);
  });

  // E3. Repository side effects
  it('E3: scan execution leaves zero working tree residue and no lock files in .git/', async () => {
    fixture.modifyFile('packages/core-engine/src/index.ts', 'export const sideEffectTest = 1;\n');
    fixture.stage('packages/core-engine/src/index.ts');

    await DiffScope.computeDiffScope(fixture.coreEngineDir, {
      staged: true,
      diffLines: true,
    });

    // Assert index.lock does not exist
    const lockFile = path.join(fixture.repoRoot, '.git', 'index.lock');
    expect(fs.existsSync(lockFile)).toBe(false);

    // Assert no *.lock files exist in .git
    const afterGitFiles = fs.readdirSync(path.join(fixture.repoRoot, '.git'));
    const gitLocks = afterGitFiles.filter((f) => f.endsWith('.lock'));
    expect(gitLocks).toEqual([]);

    // Assert working tree was not polluted
    const coreFiles = fs.readdirSync(fixture.coreEngineDir);
    expect(coreFiles.sort()).toEqual(['package.json', 'src']);
  });
});
