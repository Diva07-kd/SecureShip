import { describe, it, expect } from 'vitest';
import { DiffParser, PatchPolicyViolationError } from '../src/diff-parser.js';

describe('DiffParser Strict Unified Diff Parser', () => {
  it('parses a valid single-file single-hunk unified diff', () => {
    const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -1,3 +1,3 @@
 const x = 1;
-eval(input);
+safeExecute(input);
 return x;
`;
    const parsed = DiffParser.parse(diff);
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.oldPath).toBe('src/app.ts');
    expect(parsed[0]?.newPath).toBe('src/app.ts');
    expect(parsed[0]?.hunks).toHaveLength(1);
    expect(parsed[0]?.addedLinesCount).toBe(1);
    expect(parsed[0]?.deletedLinesCount).toBe(1);
  });

  it('parses multi-hunk diff correctly', () => {
    const diff = `--- a/src/file.js
+++ b/src/file.js
@@ -1,3 +1,3 @@
 line1
-oldLine2
+newLine2
 line3
@@ -10,3 +10,3 @@
 line10
-oldLine11
+newLine11
 line12
`;
    const parsed = DiffParser.parse(diff);
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.hunks).toHaveLength(2);
    expect(parsed[0]?.addedLinesCount).toBe(2);
    expect(parsed[0]?.deletedLinesCount).toBe(2);
  });

  it('handles \\ No newline at end of file correctly', () => {
    const diff = `--- a/src/file.txt
+++ b/src/file.txt
@@ -1,2 +1,2 @@
 line1
-line2
\\ No newline at end of file
+line2_updated
\\ No newline at end of file
`;
    const parsed = DiffParser.parse(diff);
    expect(parsed[0]?.hunks[0]?.noNewlineOld).toBe(true);
    expect(parsed[0]?.hunks[0]?.noNewlineNew).toBe(true);
  });

  it('rejects empty or whitespace-only diffs with MALFORMED_DIFF', () => {
    expect(() => DiffParser.parse('')).toThrow(PatchPolicyViolationError);
    try {
      DiffParser.parse('   \n  ');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('MALFORMED_DIFF');
    }
  });

  it('rejects binary patches with BINARY_PATCH', () => {
    const gitBinary = `GIT binary patch
literal 28
zc$@)b00001000000000000000000000000000000000
`;
    try {
      DiffParser.parse(gitBinary);
      expect.fail('Should have thrown BINARY_PATCH');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('BINARY_PATCH');
    }

    const diffBinary = `Binary files a/logo.png and b/logo.png differ\n`;
    try {
      DiffParser.parse(diffBinary);
      expect.fail('Should have thrown BINARY_PATCH');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('BINARY_PATCH');
    }
  });

  it('rejects file mode changes with MODE_CHANGE', () => {
    const modeDiff = `old mode 100644
new mode 100755
--- a/run.sh
+++ b/run.sh
@@ -1,2 +1,2 @@
 echo 1
-echo 2
+echo 3
`;
    try {
      DiffParser.parse(modeDiff);
      expect.fail('Should have thrown MODE_CHANGE');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('MODE_CHANGE');
    }
  });

  it('rejects symlinks with SYMLINK', () => {
    const symlinkDiff = `new file mode 120000
--- /dev/null
+++ b/link
@@ -0,0 +1 @@
+/etc/passwd
`;
    try {
      DiffParser.parse(symlinkDiff);
      expect.fail('Should have thrown SYMLINK');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('SYMLINK');
    }
  });

  it('rejects renames with RENAME', () => {
    const renameDiff = `rename from old.js
rename to new.js
--- a/old.js
+++ b/new.js
@@ -1,2 +1,2 @@
 a
-b
+c
`;
    try {
      DiffParser.parse(renameDiff);
      expect.fail('Should have thrown RENAME');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('RENAME');
    }
  });

  it('rejects new file creation with NEW_FILE', () => {
    const newFileDiff = `--- /dev/null
+++ b/new.js
@@ -0,0 +1,2 @@
+const x = 1;
+console.log(x);
`;
    try {
      DiffParser.parse(newFileDiff);
      expect.fail('Should have thrown NEW_FILE');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('NEW_FILE');
    }
  });

  it('rejects file deletion with DELETE_FILE', () => {
    const deleteFileDiff = `--- a/deleted.js
+++ /dev/null
@@ -1,2 +0,0 @@
-const x = 1;
-console.log(x);
`;
    try {
      DiffParser.parse(deleteFileDiff);
      expect.fail('Should have thrown DELETE_FILE');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('DELETE_FILE');
    }
  });

  it('rejects absolute paths and path traversal with OUTSIDE_ROOT', () => {
    const absDiff = `--- /etc/passwd
+++ /etc/passwd
@@ -1,1 +1,1 @@
-root
+admin
`;
    try {
      DiffParser.parse(absDiff);
      expect.fail('Should have thrown OUTSIDE_ROOT');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('OUTSIDE_ROOT');
    }

    const traversalDiff = `--- a/../../secret.txt
+++ b/../../secret.txt
@@ -1,1 +1,1 @@
-old
+new
`;
    try {
      DiffParser.parse(traversalDiff);
      expect.fail('Should have thrown OUTSIDE_ROOT');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('OUTSIDE_ROOT');
    }
  });

  it('rejects hunks with count mismatch with MALFORMED_DIFF', () => {
    const badCountDiff = `--- a/src/app.js
+++ b/src/app.js
@@ -1,3 +1,3 @@
 line1
-line2
+line2_updated
`;
    try {
      DiffParser.parse(badCountDiff);
      expect.fail('Should have thrown MALFORMED_DIFF');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('MALFORMED_DIFF');
    }
  });

  it('enforces maxFiles limit with TOO_MANY_FILES', () => {
    const twoFilesDiff = `--- a/src/a.js
+++ b/src/a.js
@@ -1,2 +1,2 @@
 a
-b
+c
--- a/src/b.js
+++ b/src/b.js
@@ -1,2 +1,2 @@
 x
-y
+z
`;
    try {
      DiffParser.parse(twoFilesDiff, { maxFiles: 1 });
      expect.fail('Should have thrown TOO_MANY_FILES');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('TOO_MANY_FILES');
    }
  });

  it('enforces maxChangedLines and maxDiffBytes with TOO_MANY_LINES', () => {
    const bigDiff = `--- a/src/a.js
+++ b/src/a.js
@@ -1,2 +1,5 @@
 a
-b
+c1
+c2
+c3
+c4
`;
    try {
      DiffParser.parse(bigDiff, { maxChangedLines: 3 });
      expect.fail('Should have thrown TOO_MANY_LINES');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('TOO_MANY_LINES');
    }

    try {
      DiffParser.parse(bigDiff, { maxDiffBytes: 20 });
      expect.fail('Should have thrown TOO_MANY_LINES');
    } catch (e: unknown) {
      expect((e as PatchPolicyViolationError).code).toBe('TOO_MANY_LINES');
    }
  });
});
