import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { DiffScope, type LineRange } from '../src/git/diff-scope.js';
import { SafeProcessRunner } from '../src/sandbox/safe-process-runner.js';
import type { NormalizedFinding } from '@secureship/contracts';

describe('DiffScope & Git Safety Unit Suite', () => {
  let tempRepo: string;

  beforeEach(async () => {
    tempRepo = mkdtempSync(path.join(tmpdir(), 'git-diff-test-'));
  });

  afterEach(() => {
    try {
      rmSync(tempRepo, { recursive: true, force: true });
    } catch {}
  });

  function makeFinding(
    filePath: string,
    line: number,
    category: 'SAST' | 'SECRET' = 'SAST'
  ): NormalizedFinding {
    return {
      id: 'f-1',
      fingerprint: 'a'.repeat(64),
      ruleId: 'r1',
      scannerName: 'opengrep',
      category,
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: { filePath, startLine: line, endLine: line },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Finding',
      description: 'Finding',
      cweIds: [],
      evidence: [{ scannerName: 'opengrep', scannerRuleId: 'r1', message: 'Test' }],
      createdAt: new Date().toISOString(),
    };
  }

  it('Git Safety: strictly validates refs and rejects option injection attempts', () => {
    // Rejects refs starting with - (CLI option injection)
    expect(() => DiffScope.validateRef('--upload-pack=x')).toThrow(
      /Invalid git reference .* starting with '-' are disallowed/
    );
    expect(() => DiffScope.validateRef('--upload-pack=malicious')).toThrow(/starting with '-'/);
    expect(() => DiffScope.validateRef('-x')).toThrow(/starting with '-'/);

    // Rejects shell metacharacters and injection strings
    expect(() => DiffScope.validateRef('; touch pwned')).toThrow(/disallowed characters/);
    expect(() => DiffScope.validateRef('HEAD; rm -rf /')).toThrow(/disallowed characters/);
    expect(() => DiffScope.validateRef('HEAD|cat /etc/passwd')).toThrow(/disallowed characters/);
    expect(() => DiffScope.validateRef('HEAD`calc`')).toThrow(/disallowed characters/);
    expect(() => DiffScope.validateRef('HEAD$(whoami)')).toThrow(/disallowed characters/);

    // Valid refs pass cleanly (including git revision selectors)
    expect(() => DiffScope.validateRef('main')).not.toThrow();
    expect(() => DiffScope.validateRef('origin/master')).not.toThrow();
    expect(() => DiffScope.validateRef('HEAD~1')).not.toThrow();
    expect(() => DiffScope.validateRef('refs/heads/feature^1')).not.toThrow();
    expect(() => DiffScope.validateRef('v1.0.0')).not.toThrow();
    expect(() => DiffScope.validateRef('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2')).not.toThrow();
  });

  it('parses unified diff hunks into line ranges correctly', () => {
    const diffSample = `
diff --git a/src/app.ts b/src/app.ts
--- a/src/app.ts
+++ b/src/app.ts
@@ -10,3 +15,5 @@
+new code 1
+new code 2
+new code 3
+new code 4
+new code 5
@@ -50,0 +60,2 @@
+another line 1
+another line 2
`;
    const map = new Map<string, LineRange[]>();
    DiffScope.parseHunkRanges(diffSample, map);

    const ranges = map.get('src/app.ts');
    expect(ranges).toBeDefined();
    expect(ranges).toHaveLength(2);

    // First hunk: +15, 5 lines -> lines 15 to 19
    expect(ranges![0]).toEqual({ startLine: 15, endLine: 19 });

    // Second hunk: +60, 2 lines -> lines 60 to 61
    expect(ranges![1]).toEqual({ startLine: 60, endLine: 61 });
  });

  it('isFindingInScope checks file and line ranges properly', () => {
    const scope = {
      isDiffMode: true,
      changedFiles: new Set(['src/app.ts', 'src/secrets.ts']),
      fileLineRanges: new Map([['src/app.ts', [{ startLine: 15, endLine: 20 }]]]),
    };

    // Unmodified file is out of scope
    const fOutside = makeFinding('src/other.ts', 15);
    expect(DiffScope.isFindingInScope(fOutside, scope)).toBe(false);

    // Modified file, but outside changed lines when diffLinesMode is active
    const fLineMiss = makeFinding('src/app.ts', 10);
    expect(DiffScope.isFindingInScope(fLineMiss, scope, true)).toBe(false);

    // Modified file and within changed lines
    const fLineHit = makeFinding('src/app.ts', 18);
    expect(DiffScope.isFindingInScope(fLineHit, scope, true)).toBe(true);

    // Secret finding in diff mode inspects entire changed file regardless of line
    const fSecret = makeFinding('src/app.ts', 5, 'SECRET');
    expect(DiffScope.isFindingInScope(fSecret, scope, true)).toBe(true);
  });

  it('runs against real git repository in temp directory', async () => {
    // 1. Initialize git repo
    await SafeProcessRunner.run('git', ['init'], { cwd: tempRepo });
    await SafeProcessRunner.run('git', ['config', 'user.email', 'test@secureship.dev'], {
      cwd: tempRepo,
    });
    await SafeProcessRunner.run('git', ['config', 'user.name', 'SecureShip Tester'], {
      cwd: tempRepo,
    });

    // 2. Create initial commit
    const fileA = path.join(tempRepo, 'fileA.ts');
    writeFileSync(fileA, 'const x = 1;\n', 'utf-8');
    await SafeProcessRunner.run('git', ['add', '.'], { cwd: tempRepo });
    await SafeProcessRunner.run('git', ['commit', '-m', 'Initial commit'], { cwd: tempRepo });

    // 3. Modify fileA and stage it
    writeFileSync(fileA, 'const x = 1;\nconst y = 2;\n', 'utf-8');
    await SafeProcessRunner.run('git', ['add', '.'], { cwd: tempRepo });

    // 4. Compute staged diff scope
    const stagedScope = await DiffScope.computeDiffScope(tempRepo, {
      staged: true,
      diffLines: true,
    });
    expect(stagedScope.isDiffMode).toBe(true);
    expect(stagedScope.changedFiles.has('fileA.ts')).toBe(true);

    // 5. Add an untracked file and test working tree mode
    const fileUntracked = path.join(tempRepo, 'untracked.ts');
    writeFileSync(fileUntracked, 'const secret = "untracked";\n', 'utf-8');

    const workingTreeScope = await DiffScope.computeDiffScope(tempRepo, { diffRef: 'HEAD' });
    expect(workingTreeScope.changedFiles.has('untracked.ts')).toBe(true);
  });

  it('evaluates isFindingInScope across all modes and categories', () => {
    const findingA = makeFinding('fileA.ts', 15, 'SAST');
    const secretFinding = makeFinding('fileA.ts', 15, 'SECRET');
    const findingB = makeFinding('fileB.ts', 15, 'SAST');

    // 1. Full scan mode (isDiffMode = false) -> always in scope
    const fullScope = {
      isDiffMode: false,
      changedFiles: new Set<string>(),
      fileLineRanges: new Map<string, LineRange[]>(),
    };
    expect(DiffScope.isFindingInScope(findingA, fullScope)).toBe(true);

    // 2. Diff mode with file absent -> out of scope
    const diffScope = {
      isDiffMode: true,
      changedFiles: new Set<string>(['fileA.ts']),
      fileLineRanges: new Map<string, LineRange[]>([
        ['fileA.ts', [{ startLine: 10, endLine: 20 }]],
      ]),
    };
    expect(DiffScope.isFindingInScope(findingB, diffScope)).toBe(false);

    // 3. Diff mode with SECRET category -> in scope regardless of lines
    expect(DiffScope.isFindingInScope(secretFinding, diffScope, true)).toBe(true);

    // 4. Diff mode with diffLines active: line within hunk
    expect(DiffScope.isFindingInScope(findingA, diffScope, true)).toBe(true);

    // 5. Diff mode with diffLines active: line outside hunk
    const findingOutside = makeFinding('fileA.ts', 50, 'SAST');
    expect(DiffScope.isFindingInScope(findingOutside, diffScope, true)).toBe(false);

    // 6. Diff mode with diffLines active but no line ranges recorded -> fallback true
    const scopeWithoutRanges = {
      isDiffMode: true,
      changedFiles: new Set<string>(['fileA.ts']),
      fileLineRanges: new Map<string, LineRange[]>(),
    };
    expect(DiffScope.isFindingInScope(findingOutside, scopeWithoutRanges, true)).toBe(true);
  });

  it('Container Defense: executes diff-scope cleanly when SECURESHIP_CONTAINER=1', async () => {
    // 1. Initialize git repo
    await SafeProcessRunner.run('git', ['init'], { cwd: tempRepo });
    await SafeProcessRunner.run('git', ['config', 'user.email', 'test@secureship.dev'], {
      cwd: tempRepo,
    });
    await SafeProcessRunner.run('git', ['config', 'user.name', 'SecureShip Tester'], {
      cwd: tempRepo,
    });

    const fileA = path.join(tempRepo, 'fileA.ts');
    writeFileSync(fileA, 'const x = 1;\n', 'utf-8');
    await SafeProcessRunner.run('git', ['add', '.'], { cwd: tempRepo });
    await SafeProcessRunner.run('git', ['commit', '-m', 'Initial commit'], { cwd: tempRepo });

    // Modify file
    writeFileSync(fileA, 'const x = 2;\n', 'utf-8');

    const originalEnv = process.env.SECURESHIP_CONTAINER;
    try {
      process.env.SECURESHIP_CONTAINER = '1';
      const scope = await DiffScope.computeDiffScope(tempRepo, { diffRef: 'HEAD' });
      expect(scope.isDiffMode).toBe(true);
      expect(scope.changedFiles.has('fileA.ts')).toBe(true);
    } finally {
      if (originalEnv === undefined) {
        delete process.env.SECURESHIP_CONTAINER;
      } else {
        process.env.SECURESHIP_CONTAINER = originalEnv;
      }
    }
  });
});
