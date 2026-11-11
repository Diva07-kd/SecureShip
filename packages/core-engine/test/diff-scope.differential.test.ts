import { describe, it, expect, beforeEach, afterEach, vi, expectTypeOf } from 'vitest';
import {
  DiffScope,
  type DiffScopeOptions,
  type DiffScopeResult,
  type LineRange,
} from '../src/git/diff-scope.js';
import { DiffScope as DiffScopeBaseline } from './fixtures/diff-scope.baseline.js';
import { MonorepoFixture } from './fixtures/monorepo.js';
import type { NormalizedFinding } from '@secureship/contracts';

describe('Layer D & Layer A & Layer H - Differential, Anchors & Type Compatibility', () => {
  let fixture: MonorepoFixture;

  beforeEach(() => {
    fixture = MonorepoFixture.create();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    fixture.cleanup();
  });

  // Layer A: Red/Green Anchors (A1)
  describe('Layer A: Red/Green Anchors (A1)', () => {
    it('A1: baseline crashes on subdirectory target while remediated DiffScope resolves', async () => {
      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const mod = 1;\n');
      fixture.stage('packages/core-engine/src/index.ts');

      const expectedI2Message = `Directory '${fixture.coreEngineDir}' is not a git repository. Incremental scan requires an initialized git repository.`;

      // 1. Staged mode
      await expect(
        DiffScopeBaseline.computeDiffScope(fixture.coreEngineDir, { staged: true })
      ).rejects.toThrow(expectedI2Message);

      const stagedRemediated = await DiffScope.computeDiffScope(fixture.coreEngineDir, {
        staged: true,
      });
      expect(stagedRemediated.isDiffMode).toBe(true);
      expect(stagedRemediated.targetRelativeFiles).toEqual(['src/index.ts']);

      // 2. diffRef mode
      await expect(
        DiffScopeBaseline.computeDiffScope(fixture.coreEngineDir, { diffRef: 'HEAD' })
      ).rejects.toThrow(expectedI2Message);

      const diffRefRemediated = await DiffScope.computeDiffScope(fixture.coreEngineDir, {
        diffRef: 'HEAD',
      });
      expect(diffRefRemediated.isDiffMode).toBe(true);
      expect(diffRefRemediated.targetRelativeFiles).toEqual(['src/index.ts']);

      // 3. diffLines mode
      await expect(
        DiffScopeBaseline.computeDiffScope(fixture.coreEngineDir, {
          staged: true,
          diffLines: true,
        })
      ).rejects.toThrow(expectedI2Message);

      const diffLinesRemediated = await DiffScope.computeDiffScope(fixture.coreEngineDir, {
        staged: true,
        diffLines: true,
      });
      expect(diffLinesRemediated.isDiffMode).toBe(true);
      expect(diffLinesRemediated.targetRelativeFiles).toEqual(['src/index.ts']);
    });
  });

  // Layer D: Differential Regression against Baseline at Repo Root
  describe('Layer D: Differential Regression against Baseline (Root Target)', () => {
    it('D1: staged mode matches baseline exactly on root target', async () => {
      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const stagedDiff = 1;\n');
      fixture.stage('packages/core-engine/src/index.ts');

      const baselineScope = await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {
        staged: true,
      });
      const remediatedScope = await DiffScope.computeDiffScope(fixture.repoRoot, { staged: true });

      expect(remediatedScope.isDiffMode).toBe(baselineScope.isDiffMode);
      expect(Array.from(remediatedScope.changedFiles).sort()).toEqual(
        Array.from(baselineScope.changedFiles).sort()
      );
      expect(remediatedScope.fileLineRanges).toEqual(baselineScope.fileLineRanges);
    });

    it('D2: diffRef HEAD mode matches baseline exactly on root target', async () => {
      fixture.modifyFile('packages/core-engine/src/index.ts', 'export const headDiff = 2;\n');
      fixture.addFile('packages/core-engine/src/untracked-leaf.ts', 'export const leaf = 1;\n');

      const baselineScope = await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {
        diffRef: 'HEAD',
      });
      const remediatedScope = await DiffScope.computeDiffScope(fixture.repoRoot, {
        diffRef: 'HEAD',
      });

      expect(remediatedScope.isDiffMode).toBe(baselineScope.isDiffMode);
      expect(Array.from(remediatedScope.changedFiles).sort()).toEqual(
        Array.from(baselineScope.changedFiles).sort()
      );
      expect(remediatedScope.fileLineRanges).toEqual(baselineScope.fileLineRanges);
    });

    it('D3: diffRef HEAD~1 mode matches baseline exactly on root target', async () => {
      fixture.modifyFile('docs/readme.md', '# Updated Readme for HEAD~1\n');
      fixture.commitAll('Commit for HEAD~1 test');

      const baselineScope = await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {
        diffRef: 'HEAD~1',
      });
      const remediatedScope = await DiffScope.computeDiffScope(fixture.repoRoot, {
        diffRef: 'HEAD~1',
      });

      expect(remediatedScope.isDiffMode).toBe(baselineScope.isDiffMode);
      expect(Array.from(remediatedScope.changedFiles).sort()).toEqual(
        Array.from(baselineScope.changedFiles).sort()
      );
      expect(remediatedScope.fileLineRanges).toEqual(baselineScope.fileLineRanges);
    });

    it('D4: staged + diffLines mode matches baseline hunk ranges exactly on root target', async () => {
      fixture.modifyLines('packages/core-engine/src/index.ts', 3, 4, [
        'export const diff3 = 3;',
        'export const diff4 = 4;',
      ]);
      fixture.stage('packages/core-engine/src/index.ts');

      const baselineScope = await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {
        staged: true,
        diffLines: true,
      });
      const remediatedScope = await DiffScope.computeDiffScope(fixture.repoRoot, {
        staged: true,
        diffLines: true,
      });

      expect(remediatedScope.isDiffMode).toBe(baselineScope.isDiffMode);
      expect(Array.from(remediatedScope.changedFiles).sort()).toEqual(
        Array.from(baselineScope.changedFiles).sort()
      );

      const baselineRanges = baselineScope.fileLineRanges.get('packages/core-engine/src/index.ts');
      const remediatedRanges = remediatedScope.fileLineRanges.get(
        'packages/core-engine/src/index.ts'
      );
      expect(remediatedRanges).toEqual(baselineRanges);
    });

    it('D5: diffRef + diffLines mode matches baseline hunk ranges exactly on root target', async () => {
      fixture.modifyLines('packages/core-engine/src/index.ts', 1, 2, [
        'export const diff1 = 100;',
        'export const diff2 = 200;',
      ]);

      const baselineScope = await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {
        diffRef: 'HEAD',
        diffLines: true,
      });
      const remediatedScope = await DiffScope.computeDiffScope(fixture.repoRoot, {
        diffRef: 'HEAD',
        diffLines: true,
      });

      expect(remediatedScope.isDiffMode).toBe(baselineScope.isDiffMode);
      expect(Array.from(remediatedScope.changedFiles).sort()).toEqual(
        Array.from(baselineScope.changedFiles).sort()
      );
      expect(remediatedScope.fileLineRanges).toEqual(baselineScope.fileLineRanges);
    });

    it('D6: untracked new directory cell proves I5 and I8 directory expansion difference', async () => {
      // Create new untracked directory containing two files
      const newDirRel = 'packages/core-engine/src/untracked-folder';
      fixture.addFile(`${newDirRel}/file1.ts`, 'export const f1 = 1;\n');
      fixture.addFile(`${newDirRel}/file2.ts`, 'export const f2 = 2;\n');

      const baselineScope = await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {
        diffRef: 'HEAD',
      });
      const remediatedScope = await DiffScope.computeDiffScope(fixture.repoRoot, {
        diffRef: 'HEAD',
      });

      // Baseline contains directory entry 'packages/core-engine/src/untracked-folder/'
      expect(baselineScope.changedFiles.has('packages/core-engine/src/untracked-folder/')).toBe(
        true
      );
      expect(
        baselineScope.changedFiles.has('packages/core-engine/src/untracked-folder/file1.ts')
      ).toBe(false);

      // Remediated expands directory into individual files and omits directory entry
      expect(remediatedScope.changedFiles.has('packages/core-engine/src/untracked-folder/')).toBe(
        false
      );
      expect(
        remediatedScope.changedFiles.has('packages/core-engine/src/untracked-folder/file1.ts')
      ).toBe(true);
      expect(
        remediatedScope.changedFiles.has('packages/core-engine/src/untracked-folder/file2.ts')
      ).toBe(true);

      // Verify that this is the ONLY difference between the two sets
      const baselineWithoutDir = new Set(baselineScope.changedFiles);
      baselineWithoutDir.delete('packages/core-engine/src/untracked-folder/');

      const remediatedWithoutExpandedFiles = new Set(remediatedScope.changedFiles);
      remediatedWithoutExpandedFiles.delete('packages/core-engine/src/untracked-folder/file1.ts');
      remediatedWithoutExpandedFiles.delete('packages/core-engine/src/untracked-folder/file2.ts');

      expect(Array.from(remediatedWithoutExpandedFiles).sort()).toEqual(
        Array.from(baselineWithoutDir).sort()
      );
    });

    it('D7: non-diff mode returns deeply equal object with identical base keys', async () => {
      const baselineScope = await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {});
      const remediatedScope = await DiffScope.computeDiffScope(fixture.repoRoot, {});

      expect(remediatedScope.isDiffMode).toBe(baselineScope.isDiffMode);
      expect(remediatedScope.changedFiles).toEqual(baselineScope.changedFiles);
      expect(remediatedScope.fileLineRanges).toEqual(baselineScope.fileLineRanges);

      // Base keys match
      const baselineKeys = Object.keys(baselineScope).sort();
      const remediatedKeys = Object.keys(remediatedScope).sort();
      expect(remediatedKeys).toEqual(baselineKeys);
    });

    it('D8: binary and deleted files match baseline exactly on root target', async () => {
      // Add binary file
      fixture.addBinaryFile('packages/core-engine/src/blob.bin', Buffer.from([1, 2, 3]));
      // Delete file
      fixture.deleteFile('packages/cli/src/main.ts');
      fixture.stage(['packages/core-engine/src/blob.bin', 'packages/cli/src/main.ts']);

      const baselineScope = await DiffScopeBaseline.computeDiffScope(fixture.repoRoot, {
        staged: true,
      });
      const remediatedScope = await DiffScope.computeDiffScope(fixture.repoRoot, { staged: true });

      expect(remediatedScope.isDiffMode).toBe(baselineScope.isDiffMode);
      expect(Array.from(remediatedScope.changedFiles).sort()).toEqual(
        Array.from(baselineScope.changedFiles).sort()
      );
      expect(remediatedScope.fileLineRanges).toEqual(baselineScope.fileLineRanges);
    });
  });

  // Layer H: Type and API Compatibility
  describe('Layer H: Type and API Compatibility (H1)', () => {
    it('H1: preserves signatures and validates additive optional fields', () => {
      // 1. computeDiffScope signature
      expectTypeOf(DiffScope.computeDiffScope).parameters.toEqualTypeOf<
        [string, DiffScopeOptions?]
      >();
      expectTypeOf(DiffScope.computeDiffScope).returns.resolves.toMatchTypeOf<DiffScopeResult>();

      // 2. isFindingInScope signature
      expectTypeOf(DiffScope.isFindingInScope).parameters.toEqualTypeOf<
        [NormalizedFinding, DiffScopeResult, boolean?]
      >();
      expectTypeOf(DiffScope.isFindingInScope).returns.toEqualTypeOf<boolean>();

      // 3. parseHunkRanges signature
      expectTypeOf(DiffScope.parseHunkRanges).parameters.toEqualTypeOf<
        [string, Map<string, LineRange[]>]
      >();
      expectTypeOf(DiffScope.parseHunkRanges).returns.toEqualTypeOf<void>();

      // 4. validateRef signature
      expectTypeOf(DiffScope.validateRef).parameters.toEqualTypeOf<[string?]>();
      expectTypeOf(DiffScope.validateRef).returns.toEqualTypeOf<void>();

      // 5. Additive optional members on DiffScopeResult
      expectTypeOf<DiffScopeResult>().toHaveProperty('repoRoot');
      expectTypeOf<DiffScopeResult>().toHaveProperty('repoPrefix');
      expectTypeOf<DiffScopeResult>().toHaveProperty('targetRelativeFiles');

      // 6. Existing object literal without optional members compiles as DiffScopeResult
      const legacyLiteral: DiffScopeResult = {
        isDiffMode: true,
        changedFiles: new Set<string>(['src/index.ts']),
        fileLineRanges: new Map<string, LineRange[]>(),
      };
      expect(legacyLiteral.isDiffMode).toBe(true);
      expect(legacyLiteral.repoRoot).toBeUndefined();
      expect(legacyLiteral.repoPrefix).toBeUndefined();
      expect(legacyLiteral.targetRelativeFiles).toBeUndefined();
    });
  });
});
