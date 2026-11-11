import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { DiffScope } from '../src/git/diff-scope.js';
import { SafeProcessRunner } from '../src/sandbox/safe-process-runner.js';
import { MonorepoFixture } from './fixtures/monorepo.js';

describe('Layer B - Repository Discovery & Error Classification', () => {
  let fixture: MonorepoFixture;

  beforeEach(() => {
    fixture = MonorepoFixture.create();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    fixture.cleanup();
  });

  // B1. Targets that resolve, with exact repoPrefix and realpath(repoRoot)
  it('B1.a: resolves repository root with empty repoPrefix', async () => {
    const scope = await DiffScope.computeDiffScope(fixture.repoRoot, { staged: true });
    expect(scope.isDiffMode).toBe(true);
    expect(scope.repoPrefix).toBe('');
    expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));
  });

  it('B1.b: resolves packages/core-engine with exact prefix', async () => {
    const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });
    expect(scope.isDiffMode).toBe(true);
    expect(scope.repoPrefix).toBe('packages/core-engine');
    expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));
  });

  it('B1.c: resolves deeper subdirectory packages/core-engine/src with exact prefix', async () => {
    const scope = await DiffScope.computeDiffScope(fixture.coreEngineSrcDir, { staged: true });
    expect(scope.isDiffMode).toBe(true);
    expect(scope.repoPrefix).toBe('packages/core-engine/src');
    expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));
  });

  it('B1.d: resolves path containing spaces', async () => {
    const spaceDir = path.join(fixture.repoRoot, 'dir with spaces', 'sub space');
    fs.mkdirSync(spaceDir, { recursive: true });
    fs.writeFileSync(path.join(spaceDir, 'file.ts'), 'export const s = 1;\n', 'utf-8');
    fixture.stage('dir with spaces/sub space/file.ts');

    const scope = await DiffScope.computeDiffScope(spaceDir, { staged: true });
    expect(scope.isDiffMode).toBe(true);
    expect(scope.repoPrefix).toBe('dir with spaces/sub space');
    expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));
  });

  it('B1.e: resolves path containing non-ASCII characters', async () => {
    const nonAsciiDir = path.join(fixture.repoRoot, 'dir-ñ-ä-日本語', 'sub');
    fs.mkdirSync(nonAsciiDir, { recursive: true });
    fs.writeFileSync(path.join(nonAsciiDir, 'file.ts'), 'export const u = 1;\n', 'utf-8');
    fixture.stage('dir-ñ-ä-日本語/sub/file.ts');

    const scope = await DiffScope.computeDiffScope(nonAsciiDir, { staged: true });
    expect(scope.isDiffMode).toBe(true);

    let expectedPrefix = 'dir-ñ-ä-日本語/sub';
    let actualPrefix = scope.repoPrefix!;
    if (process.platform === 'darwin') {
      // macOS HFS+/APFS decomposes Unicode filenames to NFD. We compare under NFC.
      expectedPrefix = expectedPrefix.normalize('NFC');
      actualPrefix = actualPrefix.normalize('NFC');
    }
    expect(actualPrefix).toBe(expectedPrefix);
    expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));
  });

  it('B1.f: resolves directory named [app] preserving literal brackets', async () => {
    const bracketDir = path.join(fixture.repoRoot, '[app]');
    fs.mkdirSync(bracketDir, { recursive: true });
    fs.writeFileSync(path.join(bracketDir, 'page.ts'), 'export const page = 1;\n', 'utf-8');
    fixture.stage('[app]/page.ts');

    const scope = await DiffScope.computeDiffScope(bracketDir, { staged: true });
    expect(scope.isDiffMode).toBe(true);
    expect(scope.repoPrefix).toBe('[app]');
    expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));
  });

  it('B1.g: (POSIX only) resolves we*ird and directory starting with :', async () => {
    if (process.platform === 'win32') {
      console.log(
        'git suite skipped: Windows NTFS/FAT rejects characters * and : in directory paths.'
      );
      return;
    }

    const weirdDir = path.join(fixture.repoRoot, 'we*ird');
    const colonDir = path.join(fixture.repoRoot, ':colon-dir');
    fs.mkdirSync(weirdDir, { recursive: true });
    fs.mkdirSync(colonDir, { recursive: true });
    fs.writeFileSync(path.join(weirdDir, 'f.ts'), 'export const w = 1;\n', 'utf-8');
    fs.writeFileSync(path.join(colonDir, 'f.ts'), 'export const c = 1;\n', 'utf-8');
    fixture.stage(['we*ird/f.ts', ':colon-dir/f.ts']);

    const scopeWeird = await DiffScope.computeDiffScope(weirdDir, { staged: true });
    expect(scopeWeird.repoPrefix).toBe('we*ird');
    expect(fs.realpathSync(scopeWeird.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));

    const scopeColon = await DiffScope.computeDiffScope(colonDir, { staged: true });
    expect(scopeColon.repoPrefix).toBe(':colon-dir');
    expect(fs.realpathSync(scopeColon.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));
  });

  // B2. Linked worktree
  it('B2: linked worktree root and subdirectory resolve with statSync(.git).isFile()', async () => {
    const wt = fixture.createLinkedWorktree('wt-b2-branch');
    try {
      const gitFilePath = path.join(wt.worktreeDir, '.git');
      expect(fs.statSync(gitFilePath).isFile()).toBe(true);

      const wtCoreDir = path.join(wt.worktreeDir, 'packages', 'core-engine');
      const wtFile = path.join(wtCoreDir, 'src', 'index.ts');
      fs.writeFileSync(wtFile, 'export const wtEdit = true;\n', 'utf-8');
      fixture.execGit(['add', 'packages/core-engine/src/index.ts'], wt.worktreeDir);

      // Worktree root
      const rootScope = await DiffScope.computeDiffScope(wt.worktreeDir, { staged: true });
      expect(rootScope.repoPrefix).toBe('');
      expect(fs.realpathSync(rootScope.repoRoot!)).toBe(fs.realpathSync(wt.worktreeDir));
      expect(Array.from(rootScope.changedFiles)).toEqual(['packages/core-engine/src/index.ts']);

      // Worktree subdirectory
      const subScope = await DiffScope.computeDiffScope(wtCoreDir, { staged: true });
      expect(subScope.repoPrefix).toBe('packages/core-engine');
      expect(fs.realpathSync(subScope.repoRoot!)).toBe(fs.realpathSync(wt.worktreeDir));
      expect(Array.from(subScope.changedFiles).sort()).toEqual([
        'packages/core-engine/src/index.ts',
        'src/index.ts',
      ]);
    } finally {
      wt.cleanup();
    }
  });

  it('B2.b: gitlink pointer (submodule-style .git file) resolves correctly', async () => {
    const subRepo = fixture.createNestedRepo('packages/submodule-pointer');
    try {
      const gitFilePath = path.join(subRepo.repoDir, '.git');
      expect(fs.statSync(gitFilePath).isDirectory()).toBe(true);

      const modulesDir = path.join(fixture.repoRoot, '.git', 'modules', 'submodule-pointer');
      fs.mkdirSync(modulesDir, { recursive: true });
      for (const item of fs.readdirSync(gitFilePath)) {
        fs.renameSync(path.join(gitFilePath, item), path.join(modulesDir, item));
      }
      fs.rmdirSync(gitFilePath);
      fs.writeFileSync(gitFilePath, `gitdir: ${modulesDir}\n`, 'utf-8');
      expect(fs.statSync(gitFilePath).isFile()).toBe(true);

      const scope = await DiffScope.computeDiffScope(subRepo.repoDir, { staged: true });
      expect(scope.isDiffMode).toBe(true);
      expect(scope.repoPrefix).toBe('');
      expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(subRepo.repoDir));
    } finally {
      subRepo.cleanup();
    }
  });

  // B3. Nested independent repository inside the outer one
  it('B3: nested independent repository resolves to the inner repo and ignores outer changes', async () => {
    const nested = fixture.createNestedRepo('packages/nested-standalone');
    try {
      const nestedSrc = path.join(nested.repoDir, 'src');
      fs.mkdirSync(nestedSrc, { recursive: true });
      fs.writeFileSync(path.join(nestedSrc, 'inner.ts'), 'export const inner = 1;\n', 'utf-8');

      // Commit in nested
      const fullArgs = ['-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false'];
      fixture.execGit([...fullArgs, 'add', '.'], nested.repoDir);
      fixture.execGit([...fullArgs, 'commit', '-m', 'Initial nested commit'], nested.repoDir);

      // Stage an edit in outer repo
      fixture.modifyFile('docs/readme.md', '# Outer Repo Modification\n');
      fixture.stage('docs/readme.md');

      // Stage an edit in nested repo
      fs.writeFileSync(path.join(nestedSrc, 'inner.ts'), 'export const inner = 2;\n', 'utf-8');
      fixture.execGit([...fullArgs, 'add', 'src/inner.ts'], nested.repoDir);

      // Target nested repo subdirectory
      const scope = await DiffScope.computeDiffScope(nestedSrc, { staged: true });
      expect(scope.repoPrefix).toBe('src');
      expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(nested.repoDir));
      expect(Array.from(scope.changedFiles).sort()).toEqual(['inner.ts', 'src/inner.ts']);
      expect(scope.changedFiles.has('docs/readme.md')).toBe(false);
    } finally {
      nested.cleanup();
    }
  });

  // B4. Symlink (junction on win32) to a repo subdirectory
  it('B4: symlink to repo subdirectory resolves with correct prefix and dual namespaces (M4 guard)', async () => {
    const symlinkDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-symlink-b4-'));
    const linkPath = path.join(symlinkDir, 'core-link');
    try {
      const symlinkType = process.platform === 'win32' ? 'junction' : 'dir';
      fs.symlinkSync(fixture.coreEngineDir, linkPath, symlinkType);

      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const symlinkVal = 123;\n');
      fixture.stage('packages/core-engine/src/index.ts');

      const scope = await DiffScope.computeDiffScope(linkPath, { staged: true });
      expect(scope.repoPrefix).toBe('packages/core-engine');
      expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));
      expect(Array.from(scope.changedFiles).sort()).toEqual([
        'packages/core-engine/src/index.ts',
        'src/index.ts',
      ]);
    } finally {
      try {
        fs.rmSync(symlinkDir, { recursive: true, force: true });
      } catch {}
    }
  });

  // B5. Relative target string built with path.relative(process.cwd(), dir)
  it('B5: relative target string built with path.relative resolves cleanly', async () => {
    let relTarget: string;
    try {
      relTarget = path.relative(process.cwd(), fixture.coreEngineDir);
      if (
        path.isAbsolute(relTarget) ||
        relTarget.startsWith(path.parse(fixture.coreEngineDir).root)
      ) {
        console.log('git suite skipped: relative path cross-drive impossible on Windows');
        return;
      }
    } catch {
      console.log('git suite skipped: path.relative threw on drive mismatch');
      return;
    }

    const scope = await DiffScope.computeDiffScope(relTarget, { staged: true });
    expect(scope.repoPrefix).toBe('packages/core-engine');
    expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));
  });

  // B6. Byte-exact I2 message for non-git dir, nonexistent path, file, and bare repo
  it('B6.a: byte-exact I2 message for nonexistent path', async () => {
    const nonExistent = path.join(fixture.repoRoot, 'nonexistent-path-abc');
    await expect(DiffScope.computeDiffScope(nonExistent, { staged: true })).rejects.toThrow(
      `Directory '${nonExistent}' is not a git repository. Incremental scan requires an initialized git repository.`
    );
  });

  it('B6.b: byte-exact I2 message for regular file target', async () => {
    const filePath = path.join(fixture.coreEngineSrcDir, 'index.ts');
    await expect(DiffScope.computeDiffScope(filePath, { staged: true })).rejects.toThrow(
      `Directory '${filePath}' is not a git repository. Incremental scan requires an initialized git repository.`
    );
  });

  it('B6.c: byte-exact I2 message for standalone non-git directory', async () => {
    const nonGit = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-standalone-nongit-'));
    try {
      let cur = nonGit;
      let hasGitAncestor = false;
      while (true) {
        if (fs.existsSync(path.join(cur, '.git'))) {
          hasGitAncestor = true;
          break;
        }
        const parent = path.dirname(cur);
        if (parent === cur) break;
        cur = parent;
      }

      if (hasGitAncestor) {
        console.log(`git suite skipped: ancestor of ${nonGit} contains .git repository`);
        return;
      }

      await expect(DiffScope.computeDiffScope(nonGit, { staged: true })).rejects.toThrow(
        `Directory '${nonGit}' is not a git repository. Incremental scan requires an initialized git repository.`
      );
    } finally {
      try {
        fs.rmSync(nonGit, { recursive: true, force: true });
      } catch {}
    }
  });

  it('B6.d: byte-exact I2 message for bare repository (no .git directory child or ancestor)', async () => {
    const bareDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-bare-'));
    try {
      fixture.execGit(['init', '--bare'], bareDir);
      // Bare repo contains HEAD, config, objects/, refs/ directly; it has NO .git subdirectory or ancestor
      await expect(DiffScope.computeDiffScope(bareDir, { staged: true })).rejects.toThrow(
        `Directory '${bareDir}' is not a git repository. Incremental scan requires an initialized git repository.`
      );
    } finally {
      try {
        fs.rmSync(bareDir, { recursive: true, force: true });
      } catch {}
    }
  });

  // B7. Target inside .git directory throws Unable to resolve, NOT I2
  it('B7: target inside .git directory throws worktree error and NOT the I2 message', async () => {
    const gitDir = path.join(fixture.repoRoot, '.git');
    await expect(DiffScope.computeDiffScope(gitDir, { staged: true })).rejects.toThrow(
      `Unable to resolve the git repository for '${gitDir}': fatal: this operation must be run in a work tree`
    );
  });

  // B8. Non-diff mode returns baseline-identical object without git calls; invalid ref throws before git
  it('B8.a: non-diff mode returns baseline-identical object with 0 SafeProcessRunner calls', async () => {
    const spy = vi.spyOn(SafeProcessRunner, 'run');
    const nonGitPath = path.join(os.tmpdir(), 'arbitrary-non-git-dir-xyz');

    const result = await DiffScope.computeDiffScope(nonGitPath, {});
    expect(result.isDiffMode).toBe(false);
    expect(result.changedFiles).toEqual(new Set());
    expect(result.fileLineRanges).toEqual(new Map());
    expect(spy).toHaveBeenCalledTimes(0);
  });

  it('B8.b: invalid git ref throws validateRef error before any git call or repo check', async () => {
    const spy = vi.spyOn(SafeProcessRunner, 'run');
    const nonExistent = path.join(os.tmpdir(), 'nonexistent-ref-check-dir');

    // Leading '-' option injection attempt
    await expect(
      DiffScope.computeDiffScope(nonExistent, { diffRef: '--output=/tmp/pwn' })
    ).rejects.toThrow(
      "Invalid git reference '--output=/tmp/pwn': references starting with '-' are disallowed"
    );

    // Shell metacharacters injection attempt
    await expect(
      DiffScope.computeDiffScope(nonExistent, { diffRef: 'HEAD;rm -rf /' })
    ).rejects.toThrow(
      "Invalid git reference 'HEAD;rm -rf /': reference contains invalid or disallowed characters."
    );

    expect(spy).toHaveBeenCalledTimes(0);
  });

  // B9. Classification with mocked runner
  it('B9.a: throws Unable to run git when SafeProcessRunner throws', async () => {
    vi.spyOn(SafeProcessRunner, 'run').mockRejectedValue(new Error('ENOENT: git binary not found'));

    await expect(
      DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
    ).rejects.toThrow(
      `Unable to run git for '${fixture.coreEngineDir}': ENOENT: git binary not found`
    );
  });

  it('B9.b: throws timed out message when SafeProcessRunner reports timedOut', async () => {
    vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      stdout: '',
      stderr: '',
      exitCode: null,
      signal: 'SIGTERM',
      durationMs: 5000,
      timedOut: true,
      truncated: false,
    });

    await expect(
      DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
    ).rejects.toThrow(`Unable to run git for '${fixture.coreEngineDir}': git rev-parse timed out`);
  });

  it('B9.c: throws Unable to resolve git repository on exit 128 dubious ownership when .git ancestor exists', async () => {
    vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      stdout: '',
      stderr: "fatal: detected dubious ownership in repository at '/repo'\n",
      exitCode: 128,
      signal: null,
      durationMs: 10,
      timedOut: false,
      truncated: false,
    });

    await expect(
      DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
    ).rejects.toThrow(
      `Unable to resolve the git repository for '${fixture.coreEngineDir}': fatal: detected dubious ownership in repository at '/repo'`
    );
  });

  it('B9.d: throws I2 message on exit 128 when no .git ancestor exists', async () => {
    const standaloneDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-mock-standalone-'));
    try {
      let cur = standaloneDir;
      let hasAncestor = false;
      while (true) {
        if (fs.existsSync(path.join(cur, '.git'))) {
          hasAncestor = true;
          break;
        }
        const parent = path.dirname(cur);
        if (parent === cur) break;
        cur = parent;
      }
      if (hasAncestor) {
        console.log('git suite skipped: temp dir has git ancestor in environment');
        return;
      }

      vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
        stdout: '',
        stderr: 'fatal: not a git repository (or any of the parent directories): .git\n',
        exitCode: 128,
        signal: null,
        durationMs: 10,
        timedOut: false,
        truncated: false,
      });

      await expect(DiffScope.computeDiffScope(standaloneDir, { staged: true })).rejects.toThrow(
        `Directory '${standaloneDir}' is not a git repository. Incremental scan requires an initialized git repository.`
      );
    } finally {
      try {
        fs.rmSync(standaloneDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it('B9.e: throws I2 message when git rev-parse outputs false', async () => {
    vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      stdout: 'false\n',
      stderr: '',
      exitCode: 0,
      signal: null,
      durationMs: 10,
      timedOut: false,
      truncated: false,
    });

    await expect(
      DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
    ).rejects.toThrow(
      `Directory '${fixture.coreEngineDir}' is not a git repository. Incremental scan requires an initialized git repository.`
    );
  });

  it('B9.f: throws Unexpected output when stdout is empty, garbage, or has extra lines', async () => {
    // Empty stdout
    vi.spyOn(SafeProcessRunner, 'run').mockResolvedValueOnce({
      stdout: '\n',
      stderr: '',
      exitCode: 0,
      signal: null,
      durationMs: 10,
      timedOut: false,
      truncated: false,
    });
    await expect(
      DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
    ).rejects.toThrow(
      `Unexpected output from git while resolving the repository for '${fixture.coreEngineDir}'`
    );

    // Garbage stdout
    vi.spyOn(SafeProcessRunner, 'run').mockResolvedValueOnce({
      stdout: 'not-true-or-false\n',
      stderr: '',
      exitCode: 0,
      signal: null,
      durationMs: 10,
      timedOut: false,
      truncated: false,
    });
    await expect(
      DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
    ).rejects.toThrow(
      `Unexpected output from git while resolving the repository for '${fixture.coreEngineDir}'`
    );

    // Extra lines (> 3 lines)
    vi.spyOn(SafeProcessRunner, 'run').mockResolvedValueOnce({
      stdout: 'true\n/repo\nprefix\nextra-line-4\n',
      stderr: '',
      exitCode: 0,
      signal: null,
      durationMs: 10,
      timedOut: false,
      truncated: false,
    });
    await expect(
      DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
    ).rejects.toThrow(
      `Unexpected output from git while resolving the repository for '${fixture.coreEngineDir}'`
    );
  });

  it('B9.g: accepts trimmed stdout (2 lines) and assigns empty prefix', async () => {
    const toplevel = fixture.repoRoot;
    vi.spyOn(SafeProcessRunner, 'run').mockImplementation(async (_cmd, args = []) => {
      if (args.includes('rev-parse')) {
        return {
          stdout: `true\n${toplevel}\n`,
          stderr: '',
          exitCode: 0,
          signal: null,
          durationMs: 5,
          timedOut: false,
          truncated: false,
        };
      }
      return {
        stdout: '',
        stderr: '',
        exitCode: 0,
        signal: null,
        durationMs: 5,
        timedOut: false,
        truncated: false,
      };
    });

    const scope = await DiffScope.computeDiffScope(fixture.repoRoot, { staged: true });
    expect(scope.repoPrefix).toBe('');
    expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(toplevel));
  });

  it('B9.h: truncates stderr excerpt to at most 200 characters when .git ancestor exists', async () => {
    const longStderr = 'fatal: detected dubious ownership ' + 'a'.repeat(250) + '\n';
    vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      stdout: '',
      stderr: longStderr,
      exitCode: 128,
      signal: null,
      durationMs: 10,
      timedOut: false,
      truncated: false,
    });

    const expectedExcerpt = longStderr.trim().slice(0, 200);
    expect(expectedExcerpt.length).toBe(200);
    await expect(
      DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
    ).rejects.toThrow(
      `Unable to resolve the git repository for '${fixture.coreEngineDir}': ${expectedExcerpt}`
    );
  });

  it('B9.i: strips stack frames and multiline text when SafeProcessRunner throws', async () => {
    const errorWithStack = new Error(
      'Command failed: git rev-parse\n    at ChildProcess.exithandler (node:child_process:419:12)\n    at ...'
    );
    vi.spyOn(SafeProcessRunner, 'run').mockRejectedValue(errorWithStack);

    await expect(
      DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
    ).rejects.toThrow(
      `Unable to run git for '${fixture.coreEngineDir}': Command failed: git rev-parse`
    );
  });

  // B10. Container policy
  it('B10: container policy scopes safe.directory strictly to resolved target without wildcard', async () => {
    process.env.SECURESHIP_CONTAINER = '1';

    const recordedArgvs: string[][] = [];
    const origRun = SafeProcessRunner.run;
    vi.spyOn(SafeProcessRunner, 'run').mockImplementation(async (cmd, args = [], opts) => {
      recordedArgvs.push(args);
      return origRun(cmd, args, opts);
    });

    const resolvedTarget = path.resolve(fixture.coreEngineDir);
    const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });
    expect(scope.isDiffMode).toBe(true);

    // Verify safe.directory was passed to git commands
    expect(recordedArgvs.length).toBeGreaterThan(0);
    for (const argv of recordedArgvs) {
      const safeDirIdx = argv.findIndex((a) => a.startsWith('safe.directory='));
      if (safeDirIdx !== -1) {
        const val = argv[safeDirIdx]?.split('=')[1];
        expect(val).toBe(resolvedTarget);
        expect(val).not.toBe('*');
        expect(val).not.toBe(path.dirname(resolvedTarget));
      }
    }

    // Canary check: determine if GIT_TEST_ASSUME_DIFFERENT_OWNER reaches child via SafeProcessRunner
    process.env.GIT_TEST_ASSUME_DIFFERENT_OWNER = '1';
    const testCanary = await SafeProcessRunner.run('git', ['rev-parse', '--is-inside-work-tree'], {
      cwd: fixture.coreEngineDir,
    });
    // SafeProcessRunner sanitizes environment with SAFE_OS_ENV_KEYS allowlist, so GIT_TEST_ASSUME_DIFFERENT_OWNER is stripped
    if (testCanary.exitCode !== 0 && testCanary.stderr.includes('dubious ownership')) {
      // If it reaches child, verify subdirectory scan fails closed
      await expect(
        DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true })
      ).rejects.toThrow(/Unable to resolve the git repository for.*dubious ownership/);
    } else {
      console.log(
        'git suite skipped: GIT_TEST_ASSUME_DIFFERENT_OWNER does not reach child (filtered by SafeProcessRunner.sanitizeEnvironment safe OS allowlist).'
      );
    }
  });
});
