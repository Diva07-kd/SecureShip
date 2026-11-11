import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import { DiffScope } from '../src/git/diff-scope.js';
import { SafeProcessRunner } from '../src/sandbox/safe-process-runner.js';
import type { NormalizedFinding } from '@secureship/contracts';
import { MonorepoFixture } from './fixtures/monorepo.js';

function makeFinding(
  filePath: string,
  startLine: number,
  endLine: number,
  category: 'SAST' | 'SECRET' = 'SAST'
): NormalizedFinding {
  return {
    id: `finding-${filePath}-${startLine}`,
    fingerprint: 'a'.repeat(64),
    ruleId: 'secureship-test-rule',
    scannerName: 'opengrep',
    category,
    severity: 'HIGH',
    confidence: 'HIGH',
    reachability: 'UNKNOWN',
    location: { filePath, startLine, endLine },
    upstreamValidationStatus: 'UNKNOWN',
    verificationStatus: 'UNVERIFIED',
    scopeTag: 'PRODUCTION',
    title: 'Test Finding',
    description: 'Test finding description',
    cweIds: ['CWE-79'],
    evidence: [
      { scannerName: 'opengrep', scannerRuleId: 'secureship-test-rule', message: 'Test evidence' },
    ],
    createdAt: new Date().toISOString(),
  };
}

describe('Layer C - Scoping Matrix against Real Git', () => {
  let fixture: MonorepoFixture;

  beforeEach(() => {
    fixture = MonorepoFixture.create();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    fixture.cleanup();
  });

  // C1, C2, C3, C5: Parametrized Matrix across modes and targets
  describe('Parametrized Scoping Matrix (C1, C2, C3, C5)', () => {
    it('C1-C5 staged mode: computes exact scope for root target', async () => {
      // Modify a file in core-engine
      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const mod = 1;\n');
      fixture.stage('packages/core-engine/src/index.ts');

      // Also modify sibling and root
      fixture.modifyFile('packages/cli/src/index.ts', 'export const cliMod = 1;\n');
      fixture.modifyFile('docs/readme.md', '# Readme Edit\n');
      fixture.stage(['packages/cli/src/index.ts', 'docs/readme.md']);

      const scope = await DiffScope.computeDiffScope(fixture.repoRoot, { staged: true });

      expect(scope.isDiffMode).toBe(true);
      expect(scope.repoPrefix).toBe('');
      expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));

      const expectedFiles = [
        'docs/readme.md',
        'packages/cli/src/index.ts',
        'packages/core-engine/src/index.ts',
      ];
      expect(Array.from(scope.changedFiles).sort()).toEqual(expectedFiles);
      expect(scope.targetRelativeFiles).toEqual(expectedFiles);
    });

    it('C1-C5 staged mode: computes exact scope for packages/core-engine subdirectory target', async () => {
      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const mod = 1;\n');
      fixture.stage('packages/core-engine/src/index.ts');

      // Sibling change with same relative name and root change
      fixture.modifyFile('packages/cli/src/index.ts', 'export const cliMod = 1;\n');
      fixture.modifyFile('docs/readme.md', '# Readme Edit\n');
      fixture.stage(['packages/cli/src/index.ts', 'docs/readme.md']);

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });

      expect(scope.isDiffMode).toBe(true);
      expect(scope.repoPrefix).toBe('packages/core-engine');
      expect(fs.realpathSync(scope.repoRoot!)).toBe(fs.realpathSync(fixture.repoRoot));

      // Target relative files: ONLY src/index.ts
      expect(scope.targetRelativeFiles).toEqual(['src/index.ts']);

      // Dual namespaces in changedFiles: target-relative + repo-relative
      expect(Array.from(scope.changedFiles).sort()).toEqual([
        'packages/core-engine/src/index.ts',
        'src/index.ts',
      ]);

      // C3: Neither sibling nor root files leak
      expect(scope.changedFiles.has('packages/cli/src/index.ts')).toBe(false);
      expect(scope.changedFiles.has('docs/readme.md')).toBe(false);
    });

    it('C1-C5 staged mode: computes exact scope for deeper packages/core-engine/src target', async () => {
      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const mod = 1;\n');
      fixture.stage('packages/core-engine/src/index.ts');

      fixture.modifyFile('packages/cli/src/index.ts', 'export const cliMod = 1;\n');
      fixture.stage('packages/cli/src/index.ts');

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineSrcDir, { staged: true });

      expect(scope.isDiffMode).toBe(true);
      expect(scope.repoPrefix).toBe('packages/core-engine/src');

      expect(scope.targetRelativeFiles).toEqual(['index.ts']);
      expect(Array.from(scope.changedFiles).sort()).toEqual([
        'index.ts',
        'packages/core-engine/src/index.ts',
      ]);
    });

    it('C1-C5 diffRef HEAD mode: captures unstaged working tree changes and untracked files', async () => {
      // Modify tracked file (unstaged)
      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const mod = 2;\n');

      // Add untracked file
      fixture.addFile('packages/core-engine/src/new-untracked.ts', 'export const u = 1;\n');

      // Add untracked file in a new directory
      fixture.addFile(
        'packages/core-engine/src/subfolder/nested-untracked.ts',
        'export const n = 1;\n'
      );

      // Add file in ignored directory
      fixture.addFile(
        'packages/core-engine/ignored/should-be-ignored.ts',
        'export const ign = 1;\n'
      );

      // Sibling change unstaged
      fixture.modifyFile('packages/cli/src/index.ts', 'export const cliMod = 2;\n');

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { diffRef: 'HEAD' });

      expect(scope.isDiffMode).toBe(true);
      expect(scope.repoPrefix).toBe('packages/core-engine');

      const expectedTargetRel = [
        'src/index.ts',
        'src/new-untracked.ts',
        'src/subfolder/nested-untracked.ts',
      ];
      expect(scope.targetRelativeFiles).toEqual(expectedTargetRel);

      const expectedChangedFiles = [
        'packages/core-engine/src/index.ts',
        'packages/core-engine/src/new-untracked.ts',
        'packages/core-engine/src/subfolder/nested-untracked.ts',
        'src/index.ts',
        'src/new-untracked.ts',
        'src/subfolder/nested-untracked.ts',
      ];
      expect(Array.from(scope.changedFiles).sort()).toEqual(expectedChangedFiles);

      // Verify ignored directory did not leak
      expect(scope.changedFiles.has('ignored/should-be-ignored.ts')).toBe(false);
      expect(scope.changedFiles.has('packages/core-engine/ignored/should-be-ignored.ts')).toBe(
        false
      );
      // Verify sibling did not leak
      expect(scope.changedFiles.has('packages/cli/src/index.ts')).toBe(false);
    });

    it('C1-C5 diffRef HEAD~1 mode: compares against previous commit', async () => {
      fixture.modifyFile('packages/core-engine/src/util.ts', 'export const utilV2 = 2;\n');
      fixture.commitAll('Second commit in core-engine');

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { diffRef: 'HEAD~1' });

      expect(scope.isDiffMode).toBe(true);
      expect(scope.targetRelativeFiles).toEqual(['src/util.ts']);
      expect(Array.from(scope.changedFiles).sort()).toEqual([
        'packages/core-engine/src/util.ts',
        'src/util.ts',
      ]);
    });

    it('C3: same-named sibling change alone yields an empty scope for the target', async () => {
      // Modify ONLY packages/cli/src/index.ts
      fixture.modifyFile('packages/cli/src/index.ts', 'export const changedInCli = true;\n');
      fixture.stage('packages/cli/src/index.ts');

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });

      expect(scope.isDiffMode).toBe(true);
      expect(scope.targetRelativeFiles).toEqual([]);
      expect(scope.changedFiles.size).toBe(0);
    });

    it('C1-C5 binary file: staged binary file is registered in changedFiles but produces no line ranges', async () => {
      const binaryContent = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0x00]);
      fixture.addBinaryFile('packages/core-engine/src/binary.dat', binaryContent);
      fixture.stage('packages/core-engine/src/binary.dat');

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, {
        staged: true,
        diffLines: true,
      });

      expect(scope.isDiffMode).toBe(true);
      expect(scope.targetRelativeFiles).toEqual(['src/binary.dat']);
      expect(Array.from(scope.changedFiles).sort()).toEqual([
        'packages/core-engine/src/binary.dat',
        'src/binary.dat',
      ]);
      expect(scope.fileLineRanges.has('src/binary.dat')).toBe(false);
      expect(scope.fileLineRanges.has('packages/core-engine/src/binary.dat')).toBe(false);
    });

    it('C1-C5 chmod +x: (POSIX only) mode changes are tracked in changedFiles', async () => {
      if (process.platform === 'win32') {
        console.log(
          'git suite skipped on win32: Windows does not support POSIX executable file modes'
        );
        return;
      }

      const scriptPath = path.join(fixture.coreEngineSrcDir, 'index.ts');
      fs.chmodSync(scriptPath, 0o755);
      fixture.execGit(['add', '--chmod=+x', 'packages/core-engine/src/index.ts']);

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });
      expect(scope.isDiffMode).toBe(true);
      expect(scope.targetRelativeFiles).toEqual(['src/index.ts']);
      expect(Array.from(scope.changedFiles).sort()).toEqual([
        'packages/core-engine/src/index.ts',
        'src/index.ts',
      ]);
    });

    it('C1-C5 staged + diffLines mode: computes exact scope for root and subdirectory depths', async () => {
      fixture.modifyLines('packages/core-engine/src/index.ts', 1, 2, [
        'export const r1 = 10;',
        'export const r2 = 20;',
      ]);
      fixture.stage('packages/core-engine/src/index.ts');

      // 1. Root target
      const rootScope = await DiffScope.computeDiffScope(fixture.repoRoot, {
        staged: true,
        diffLines: true,
      });
      expect(rootScope.repoPrefix).toBe('');
      expect(rootScope.targetRelativeFiles).toEqual(['packages/core-engine/src/index.ts']);
      expect(Array.from(rootScope.changedFiles)).toEqual(['packages/core-engine/src/index.ts']);
      expect(rootScope.fileLineRanges.get('packages/core-engine/src/index.ts')).toEqual([
        { startLine: 1, endLine: 2 },
      ]);

      // 2. Subdirectory target (packages/core-engine/src)
      const srcScope = await DiffScope.computeDiffScope(fixture.coreEngineSrcDir, {
        staged: true,
        diffLines: true,
      });
      expect(srcScope.repoPrefix).toBe('packages/core-engine/src');
      expect(srcScope.targetRelativeFiles).toEqual(['index.ts']);
      expect(Array.from(srcScope.changedFiles).sort()).toEqual([
        'index.ts',
        'packages/core-engine/src/index.ts',
      ]);
      expect(srcScope.fileLineRanges.get('index.ts')).toEqual([{ startLine: 1, endLine: 2 }]);
      expect(srcScope.fileLineRanges.get('packages/core-engine/src/index.ts')).toEqual([
        { startLine: 1, endLine: 2 },
      ]);
    });

    it('C1-C5 diffRef + diffLines mode: computes exact scope for root and subdirectory depths', async () => {
      fixture.modifyLines('packages/core-engine/src/index.ts', 5, 6, [
        'export const d5 = 55;',
        'export const d6 = 66;',
      ]);

      // 1. Root target
      const rootScope = await DiffScope.computeDiffScope(fixture.repoRoot, {
        diffRef: 'HEAD',
        diffLines: true,
      });
      expect(rootScope.targetRelativeFiles).toEqual(['packages/core-engine/src/index.ts']);
      expect(rootScope.fileLineRanges.get('packages/core-engine/src/index.ts')).toEqual([
        { startLine: 5, endLine: 6 },
      ]);

      // 2. Deeper subdirectory target (packages/core-engine/src)
      const srcScope = await DiffScope.computeDiffScope(fixture.coreEngineSrcDir, {
        diffRef: 'HEAD',
        diffLines: true,
      });
      expect(srcScope.targetRelativeFiles).toEqual(['index.ts']);
      expect(srcScope.fileLineRanges.get('index.ts')).toEqual([{ startLine: 5, endLine: 6 }]);
      expect(srcScope.fileLineRanges.get('packages/core-engine/src/index.ts')).toEqual([
        { startLine: 5, endLine: 6 },
      ]);
    });
  });

  // C4: Rename and Deletion Semantics
  describe('Rename and Deletion Semantics (C4)', () => {
    it('C4.a: inside->inside rename registers only the new path', async () => {
      fixture.renameFile('packages/core-engine/src/util.ts', 'packages/core-engine/src/helper.ts');
      fixture.stage(['packages/core-engine/src/util.ts', 'packages/core-engine/src/helper.ts']);

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });

      expect(scope.targetRelativeFiles).toEqual(['src/helper.ts']);
      expect(Array.from(scope.changedFiles).sort()).toEqual([
        'packages/core-engine/src/helper.ts',
        'src/helper.ts',
      ]);
      expect(scope.changedFiles.has('src/util.ts')).toBe(false);
    });

    it('C4.b: sibling->target rename registers the new path inside target', async () => {
      fixture.renameFile('packages/cli/src/main.ts', 'packages/core-engine/src/imported.ts');
      fixture.stage(['packages/cli/src/main.ts', 'packages/core-engine/src/imported.ts']);

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });

      expect(scope.targetRelativeFiles).toEqual(['src/imported.ts']);
      expect(Array.from(scope.changedFiles).sort()).toEqual([
        'packages/core-engine/src/imported.ts',
        'src/imported.ts',
      ]);
      expect(scope.changedFiles.has('packages/cli/src/main.ts')).toBe(false);
    });

    it('C4.c: target->sibling rename registers nothing for the target', async () => {
      fixture.renameFile('packages/core-engine/src/util.ts', 'packages/cli/src/migrated-util.ts');
      fixture.stage(['packages/core-engine/src/util.ts', 'packages/cli/src/migrated-util.ts']);

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });

      expect(scope.targetRelativeFiles).toEqual([]);
      expect(scope.changedFiles.size).toBe(0);
    });

    it('C4.d: deleted file is absent from changedFiles', async () => {
      fixture.deleteFile('packages/core-engine/src/util.ts');
      fixture.stage('packages/core-engine/src/util.ts');

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });

      expect(scope.targetRelativeFiles).toEqual([]);
      expect(scope.changedFiles.size).toBe(0);
      expect(scope.changedFiles.has('src/util.ts')).toBe(false);
    });
  });

  // C6: Line Range Remapping
  describe('diffLines Range Remapping (C6)', () => {
    it('C6: calculates exact hunk line ranges for modifications, insertions, deletions, and intent-to-add', async () => {
      // 1. Modify lines 3-4 (replaces lines 3 and 4 with 2 new lines)
      fixture.modifyLines('packages/core-engine/src/index.ts', 3, 4, [
        'export const mod3 = 30;',
        'export const mod4 = 40;',
      ]);

      // 2. Insert 2 lines at line 7
      // In modified index.ts, insert after line 6
      fixture.modifyLines('packages/core-engine/src/index.ts', 7, 6, [
        'export const ins7a = 71;',
        'export const ins7b = 72;',
      ]);

      // 3. Delete 2 lines (lines 11 and 12 in the new file)
      fixture.modifyLines('packages/core-engine/src/index.ts', 11, 12, []);

      fixture.stage('packages/core-engine/src/index.ts');

      // 4. Intent-to-add file via git add -N
      fixture.addFile(
        'packages/core-engine/src/intent.ts',
        'export const i1 = 1;\nexport const i2 = 2;\n'
      );
      fixture.execGit(['add', '-N', 'packages/core-engine/src/intent.ts']);

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, {
        staged: false,
        diffRef: 'HEAD',
        diffLines: true,
      });

      const targetRanges = scope.fileLineRanges.get('src/index.ts');
      const repoRanges = scope.fileLineRanges.get('packages/core-engine/src/index.ts');

      const expectedIndexRanges = [
        { startLine: 3, endLine: 4 },
        { startLine: 7, endLine: 8 },
        { startLine: 10, endLine: 10 },
      ];
      expect(targetRanges).toEqual(expectedIndexRanges);
      expect(repoRanges).toEqual(expectedIndexRanges);
      expect(targetRanges).not.toBe(repoRanges); // distinct array instances

      // Intent-to-add ranges
      const intentTargetRanges = scope.fileLineRanges.get('src/intent.ts');
      const intentRepoRanges = scope.fileLineRanges.get('packages/core-engine/src/intent.ts');
      const expectedIntentRanges = [{ startLine: 1, endLine: 2 }];
      expect(intentTargetRanges).toEqual(expectedIntentRanges);
      expect(intentRepoRanges).toEqual(expectedIntentRanges);
      expect(intentTargetRanges).not.toBe(intentRepoRanges);

      // Verify no range exists for sibling
      expect(scope.fileLineRanges.has('packages/cli/src/index.ts')).toBe(false);
    });
  });

  // C7: Finding Correlation Integration
  describe('isFindingInScope Finding Correlation (C7)', () => {
    it('C7: integrates isFindingInScope with hunks, dual namespaces, secrets, and sibling filtering', async () => {
      // Modify lines 3-4 of packages/core-engine/src/index.ts
      fixture.modifyLines('packages/core-engine/src/index.ts', 3, 4, [
        'export const mod3 = 300;',
        'export const mod4 = 400;',
      ]);
      fixture.stage('packages/core-engine/src/index.ts');

      // Also modify sibling packages/cli/src/index.ts lines 1-2
      fixture.modifyLines('packages/cli/src/index.ts', 1, 1, ['export const cliMod = 10;']);
      fixture.stage('packages/cli/src/index.ts');

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, {
        staged: true,
        diffLines: true,
      });

      // 1. Finding inside hunk (target-relative) -> true
      const insideFinding = makeFinding('src/index.ts', 3, 3);
      expect(DiffScope.isFindingInScope(insideFinding, scope, true)).toBe(true);

      // 2. Finding just before hunk (line 2) -> false
      const beforeFinding = makeFinding('src/index.ts', 2, 2);
      expect(DiffScope.isFindingInScope(beforeFinding, scope, true)).toBe(false);

      // 3. Finding just after hunk (line 5) -> false
      const afterFinding = makeFinding('src/index.ts', 5, 5);
      expect(DiffScope.isFindingInScope(afterFinding, scope, true)).toBe(false);

      // 4. First and last line of hunk (line 3 and 4) -> true
      const firstLineFinding = makeFinding('src/index.ts', 3, 3);
      const lastLineFinding = makeFinding('src/index.ts', 4, 4);
      expect(DiffScope.isFindingInScope(firstLineFinding, scope, true)).toBe(true);
      expect(DiffScope.isFindingInScope(lastLineFinding, scope, true)).toBe(true);

      // 5. Same finding given in repo-relative namespace -> true
      const repoRelFinding = makeFinding('packages/core-engine/src/index.ts', 3, 3);
      expect(DiffScope.isFindingInScope(repoRelFinding, scope, true)).toBe(true);

      // 6. SECRET category finding anywhere in changed file -> true
      const secretFinding = makeFinding('src/index.ts', 9, 9, 'SECRET');
      expect(DiffScope.isFindingInScope(secretFinding, scope, true)).toBe(true);

      // 7. Finding in unchanged file (src/util.ts) -> false
      const unchangedFinding = makeFinding('src/util.ts', 1, 1);
      expect(DiffScope.isFindingInScope(unchangedFinding, scope, true)).toBe(false);

      // 8. Finding at src/index.ts when only sibling's src/index.ts changed (test with sibling-only scope)
      const siblingOnlyScope: typeof scope = {
        isDiffMode: true,
        changedFiles: new Set(['packages/cli/src/index.ts']),
        fileLineRanges: new Map([['packages/cli/src/index.ts', [{ startLine: 1, endLine: 2 }]]]),
        repoPrefix: 'packages/core-engine',
        targetRelativeFiles: [],
      };
      const ambiguousFinding = makeFinding('src/index.ts', 1, 1);
      expect(DiffScope.isFindingInScope(ambiguousFinding, siblingOnlyScope, true)).toBe(false);

      // 9. Finding when isDiffMode is false -> always true
      const nonDiffScope: typeof scope = {
        isDiffMode: false,
        changedFiles: new Set(),
        fileLineRanges: new Map(),
      };
      expect(DiffScope.isFindingInScope(unchangedFinding, nonDiffScope, true)).toBe(true);

      // 10. Finding in changed file with empty hunk ranges (e.g. binary or full file change) -> true
      const emptyRangesScope: typeof scope = {
        isDiffMode: true,
        changedFiles: new Set(['src/binary.dat']),
        fileLineRanges: new Map([['src/binary.dat', []]]),
      };
      const binaryFinding = makeFinding('src/binary.dat', 1, 1);
      expect(DiffScope.isFindingInScope(binaryFinding, emptyRangesScope, true)).toBe(true);
    });
  });

  // C8: Names and Character Robustness
  describe('Names and Character Robustness (C8)', () => {
    it('C8.a: handles space, unicode, leading dash, brackets, and [app] directory target', async () => {
      const spaceFile = 'packages/core-engine/src/file with spaces.ts';
      const unicodeFile = 'packages/core-engine/src/file-ñ-日本語.ts';
      const dashFile = 'packages/core-engine/src/-leading-dash.ts';
      const bracketFile = 'packages/core-engine/src/[component].tsx';

      fixture.addFile(spaceFile, 'export const s = 1;\n');
      fixture.addFile(unicodeFile, 'export const u = 1;\n');
      fixture.addFile(dashFile, 'export const d = 1;\n');
      fixture.addFile(bracketFile, 'export const b = 1;\n');

      fixture.stage([spaceFile, unicodeFile, dashFile, bracketFile]);

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });

      expect(scope.targetRelativeFiles).toContain('src/file with spaces.ts');
      expect(scope.targetRelativeFiles).toContain('src/-leading-dash.ts');
      expect(scope.targetRelativeFiles).toContain('src/[component].tsx');

      expect(scope.targetRelativeFiles).toBeDefined();
      const foundUnicode = scope.targetRelativeFiles!.some(
        (f) => f.normalize('NFC') === 'src/file-ñ-日本語.ts'.normalize('NFC')
      );
      expect(foundUnicode).toBe(true);

      // Scoping with [app] target directory
      const appDir = path.join(fixture.repoRoot, '[app]');
      fs.mkdirSync(appDir, { recursive: true });
      fs.writeFileSync(path.join(appDir, 'sub.ts'), 'export const app = 1;\n', 'utf-8');
      fixture.stage('[app]/sub.ts');

      const appScope = await DiffScope.computeDiffScope(appDir, { staged: true });
      expect(appScope.targetRelativeFiles).toEqual(['sub.ts']);
    });

    it('C8.b: (POSIX only) handles *, ?, newline, and ?? tricky.ts rename source', async () => {
      if (process.platform === 'win32') {
        console.log(
          'git suite skipped on win32: Windows NTFS/FAT rejects ?, *, and newlines in filenames'
        );
        return;
      }

      fixture.addFile('packages/core-engine/src/?? tricky.ts', 'export const tricky = 1;\n');
      fixture.addFile('packages/core-engine/src/wild*card.ts', 'export const star = 1;\n');
      fixture.commitAll('Add POSIX-only tricky files');

      fixture.renameFile(
        'packages/core-engine/src/?? tricky.ts',
        'packages/core-engine/src/untricky.ts'
      );
      fixture.stage([
        'packages/core-engine/src/?? tricky.ts',
        'packages/core-engine/src/untricky.ts',
      ]);

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });
      expect(scope.targetRelativeFiles).toContain('src/untricky.ts');
    });

    it('C8.c: (POSIX only) target directory named we*ird or :(exclude)x scopes correctly', async () => {
      if (process.platform === 'win32') {
        console.log(
          'git suite skipped on win32: Windows NTFS/FAT rejects characters * and : in directory paths'
        );
        return;
      }

      const weirdTarget = path.join(fixture.repoRoot, 'we*ird');
      fs.mkdirSync(weirdTarget, { recursive: true });
      fs.writeFileSync(path.join(weirdTarget, 'file.ts'), 'export const w = 1;\n', 'utf-8');
      fixture.stage('we*ird/file.ts');

      const weirdScope = await DiffScope.computeDiffScope(weirdTarget, { staged: true });
      expect(weirdScope.targetRelativeFiles).toEqual(['file.ts']);

      const colonTarget = path.join(fixture.repoRoot, ':(exclude)x');
      fs.mkdirSync(colonTarget, { recursive: true });
      fs.writeFileSync(path.join(colonTarget, 'file.ts'), 'export const c = 1;\n', 'utf-8');
      fixture.stage(':(exclude)x/file.ts');

      const colonScope = await DiffScope.computeDiffScope(colonTarget, { staged: true });
      expect(colonScope.targetRelativeFiles).toEqual(['file.ts']);
    });
  });

  // C9: Scale Matrix (3,000 files in target and 3,000 in sibling)
  describe('Scale Matrix (C9)', () => {
    it('C9: accurately scopes 3,000 files in target and isolates 3,000 files in sibling', async () => {
      const targetRelExpected: string[] = [];

      // Write 3,000 files in packages/core-engine/src/scale/
      const targetScaleDir = path.join(fixture.coreEngineSrcDir, 'scale');
      fs.mkdirSync(targetScaleDir, { recursive: true });
      for (let i = 0; i < 3000; i++) {
        const rel = `src/scale/t_${i}.ts`;
        targetRelExpected.push(rel);
        fs.writeFileSync(
          path.join(targetScaleDir, `t_${i}.ts`),
          `export const x = ${i};\n`,
          'utf-8'
        );
      }

      // Write 3,000 files in sibling packages/cli/src/scale/
      const siblingScaleDir = path.join(fixture.cliSrcDir, 'scale');
      fs.mkdirSync(siblingScaleDir, { recursive: true });
      for (let i = 0; i < 3000; i++) {
        fs.writeFileSync(
          path.join(siblingScaleDir, `s_${i}.ts`),
          `export const s = ${i};\n`,
          'utf-8'
        );
      }

      fixture.stage(['packages/core-engine/src/scale', 'packages/cli/src/scale']);

      const scope = await DiffScope.computeDiffScope(fixture.coreEngineDir, { staged: true });

      targetRelExpected.sort();
      expect(scope.targetRelativeFiles).toHaveLength(3000);
      expect(scope.targetRelativeFiles).toEqual(targetRelExpected);

      // Subdirectory dual namespace: 3000 target-rel + 3000 repo-rel = 6000
      expect(scope.changedFiles.size).toBe(6000);

      // Verify zero sibling files leaked
      expect(scope.targetRelativeFiles).toBeDefined();
      for (const file of scope.targetRelativeFiles!) {
        expect(file.startsWith('src/scale/t_')).toBe(true);
      }
    }, 90_000);
  });

  // C10: Command-Shape Guard
  describe('Command-Shape Guard (C10)', () => {
    it('C10: validates command arguments, option ordering, pathspec boundaries, and safe flags', async () => {
      const gitInvocations: Array<{ cmd: string; args: string[]; cwd?: string }> = [];

      const origRun = SafeProcessRunner.run;
      vi.spyOn(SafeProcessRunner, 'run').mockImplementation(async (cmd, args = [], opts) => {
        gitInvocations.push({ cmd, args, cwd: opts?.cwd });
        return origRun(cmd, args, opts);
      });

      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const guarded = true;\n');
      fixture.stage('packages/core-engine/src/index.ts');

      await DiffScope.computeDiffScope(fixture.coreEngineDir, {
        staged: true,
        diffRef: 'HEAD',
        diffLines: true,
      });

      expect(gitInvocations.length).toBeGreaterThan(0);

      const resolvedCoreEngine = path.resolve(fixture.coreEngineDir);

      for (const inv of gitInvocations) {
        expect(inv.cmd).toBe('git');
        // Every call has cwd equal to resolved target
        expect(inv.cwd).toBe(resolvedCoreEngine);

        // NO status command and NO --porcelain
        expect(inv.args).not.toContain('status');
        expect(inv.args).not.toContain('--porcelain');
        expect(inv.args).not.toContain('--porcelain=v1');

        // Pathspec assertions for diff commands
        if (inv.args.includes('diff')) {
          // --relative must be present
          expect(inv.args).toContain('--relative');

          // '--' must precede the pathspec '.'
          const dashDashIdx = inv.args.lastIndexOf('--');
          expect(dashDashIdx).toBeGreaterThan(-1);
          expect(inv.args[dashDashIdx + 1]).toBe('.');

          // No computed prefix pathspec
          for (const arg of inv.args) {
            expect(arg).not.toContain('packages/core-engine');
          }

          // User input (diffRef) must follow --end-of-options
          const endOfOptionsIdx = inv.args.indexOf('--end-of-options');
          if (endOfOptionsIdx !== -1) {
            expect(inv.args[endOfOptionsIdx + 1]).toBe('HEAD');
          }
        }

        // Hunks command specific flags
        if (inv.args.includes('-U0')) {
          expect(inv.args).toContain('--no-ext-diff');
          expect(inv.args).toContain('--no-textconv');
          expect(inv.args).toContain('--no-color');
          expect(inv.args).toContain('--src-prefix=a/');
          expect(inv.args).toContain('--dst-prefix=b/');
        }
      }
    });
  });
});
