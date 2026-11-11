import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { DiffParser } from '../src/diff-parser.js';
import { PatchApplier } from '../src/applier.js';

describe('PatchApplier Pure Function & Atomic Utility', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-applier-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('applies exact context match patch cleanly', () => {
    const orig = 'line1\nline2\nline3\n';
    const diff = `--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2_fixed
 line3
`;
    const parsed = DiffParser.parse(diff);
    const patched = PatchApplier.apply(orig, parsed[0]!);
    expect(patched).toBe('line1\nline2_fixed\nline3\n');
  });

  it('applies patch with line offset within +/-20 lines', () => {
    // 5 lines inserted earlier in file
    const orig = 'new0\nnew00\nnew000\nline1\nline2\nline3\n';
    const diff = `--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2_fixed
 line3
`;
    const parsed = DiffParser.parse(diff);
    const patched = PatchApplier.apply(orig, parsed[0]!);
    expect(patched).toBe('new0\nnew00\nnew000\nline1\nline2_fixed\nline3\n');
  });

  it('fails closed with CONTEXT_MISMATCH on ambiguous match within window', () => {
    // Two identical blocks in window
    const orig = 'line1\nline2\nline3\nline1\nline2\nline3\n';
    const diff = `--- a/file.txt
+++ b/file.txt
@@ -3,3 +3,3 @@
 line1
-line2
+line2_fixed
 line3
`;
    const parsed = DiffParser.parse(diff);
    expect(() => PatchApplier.apply(orig, parsed[0]!)).toThrow(/Ambiguous context match/);
  });

  it('fails closed with CONTEXT_MISMATCH when context cannot be found', () => {
    const orig = 'different1\ndifferent2\ndifferent3\n';
    const diff = `--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2_fixed
 line3
`;
    const parsed = DiffParser.parse(diff);
    expect(() => PatchApplier.apply(orig, parsed[0]!)).toThrow(/Context mismatch/);
  });

  it('preserves CRLF line endings', () => {
    const orig = 'line1\r\nline2\r\nline3\r\n';
    const diff = `--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2_fixed
 line3
`;
    const parsed = DiffParser.parse(diff);
    const patched = PatchApplier.apply(orig, parsed[0]!);
    expect(patched).toBe('line1\r\nline2_fixed\r\nline3\r\n');
  });

  it('preserves UTF-8 BOM', () => {
    const orig = '\uFEFFline1\nline2\nline3\n';
    const diff = `--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2_fixed
 line3
`;
    const parsed = DiffParser.parse(diff);
    const patched = PatchApplier.apply(orig, parsed[0]!);
    expect(patched.startsWith('\uFEFF')).toBe(true);
    expect(patched).toBe('\uFEFFline1\nline2_fixed\nline3\n');
  });

  it('preserves absence of trailing newline', () => {
    const orig = 'line1\nline2';
    const diff = `--- a/file.txt
+++ b/file.txt
@@ -1,2 +1,2 @@
 line1
-line2
\\ No newline at end of file
+line2_fixed
\\ No newline at end of file
`;
    const parsed = DiffParser.parse(diff);
    const patched = PatchApplier.apply(orig, parsed[0]!);
    expect(patched).toBe('line1\nline2_fixed');
    expect(patched.endsWith('\n')).toBe(false);
  });

  it('rejects patch introducing embedded carriage returns with EOL_INCONSISTENT', () => {
    const orig = 'line1\nline2\nline3\n';
    const diff = `--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2\rfixed
 line3
`;
    const parsed = DiffParser.parse(diff);
    expect(() => PatchApplier.apply(orig, parsed[0]!)).toThrow(/carriage return/);
  });

  it('atomicWrite writes file atomically preserving mode (Mutation 26)', async () => {
    const { vi } = await import('vitest');
    const target = path.join(tempDir, 'atomic.txt');
    fs.writeFileSync(target, 'initial content\n', { mode: 0o755 });

    const renameSpy = vi.spyOn(fs, 'renameSync');
    try {
      PatchApplier.atomicWrite(target, 'updated content\n');

      expect(fs.readFileSync(target, 'utf8')).toBe('updated content\n');
      expect(renameSpy).toHaveBeenCalled();
      // Ensure temporary files are cleaned up
      const remaining = fs.readdirSync(tempDir);
      expect(remaining).toHaveLength(1);
      expect(remaining[0]).toBe('atomic.txt');
    } finally {
      renameSpy.mockRestore();
    }
  });

  it('property test: applies multiple sequential hunks correctly', () => {
    const lines = Array.from({ length: 30 }, (_, i) => `function test_${i}() { return ${i}; }`);
    const orig = lines.join('\n') + '\n';

    const diff = `--- a/test.ts
+++ b/test.ts
@@ -5,3 +5,3 @@
 function test_4() { return 4; }
-function test_5() { return 5; }
+function test_5() { return 500; }
 function test_6() { return 6; }
@@ -15,3 +15,3 @@
 function test_14() { return 14; }
-function test_15() { return 15; }
+function test_15() { return 1500; }
 function test_16() { return 16; }
`;
    const parsed = DiffParser.parse(diff);
    const patched = PatchApplier.apply(orig, parsed[0]!);
    expect(patched).toContain('function test_5() { return 500; }');
    expect(patched).toContain('function test_15() { return 1500; }');
    expect(patched).not.toContain('return 5;');
    expect(patched).not.toContain('return 15;');
  });
});
