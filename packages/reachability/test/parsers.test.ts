import { describe, it, expect, beforeAll } from 'vitest';
import { TreeSitterLoader, type SupportedLanguage } from '../src/parsers/tree-sitter-loader.js';

describe('TreeSitterLoader & Parser Suite', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  it('initializes parsers for javascript, typescript, tsx, and python', () => {
    const js = TreeSitterLoader.getParser('javascript');
    expect(js.error).toBeUndefined();
    expect(js.parser).toBeDefined();

    const ts = TreeSitterLoader.getParser('typescript');
    expect(ts.error).toBeUndefined();
    expect(ts.parser).toBeDefined();

    const tsx = TreeSitterLoader.getParser('tsx');
    expect(tsx.error).toBeUndefined();
    expect(tsx.parser).toBeDefined();

    const py = TreeSitterLoader.getParser('python');
    expect(py.error).toBeUndefined();
    expect(py.parser).toBeDefined();
  });

  it('enforces file size cap and returns error for oversized content', () => {
    const largeContent = 'const x = 1;\n'.repeat(100);
    const result = TreeSitterLoader.parseFile(largeContent, 'javascript', {
      maxFileBytes: 50,
    });
    expect(result.tree).toBeNull();
    expect(result.hasError).toBe(true);
    expect(result.errorReason).toContain('exceeds configured limit');
  });

  it('detects syntax errors via rootNode.hasError', () => {
    const brokenCode = 'function broken( { const x = ;';
    const result = TreeSitterLoader.parseFile(brokenCode, 'javascript');
    expect(result.tree).toBeDefined();
    expect(result.hasError).toBe(true);
    expect(result.errorReason).toContain('ERROR or MISSING nodes');
  });

  it('parses valid code cleanly with hasError false', () => {
    const validCode = 'import express from "express";\nconst app = express();';
    const result = TreeSitterLoader.parseFile(validCode, 'javascript');
    expect(result.tree).toBeDefined();
    expect(result.hasError).toBe(false);
  });

  it('Amendment A13: tests newer Python and TS syntax and ensures no crashes', () => {
    // Python 3.12 type statement and match/case
    const python312 = `
type Point[T] = tuple[T, T]
def handle(val):
    match val:
        case [1, 2]:
            return True
        case _:
            return False
`;
    const pyResult = TreeSitterLoader.parseFile(python312, 'python');
    expect(pyResult).toBeDefined();
    // Regardless of whether modern syntax creates error nodes in 0.21.0 grammar, it must not throw and must report status cleanly
    expect(typeof pyResult.hasError).toBe('boolean');

    // TS 5.x const type parameter
    const ts5 = `function foo<const T extends readonly string[]>(values: T) { return values; }`;
    const tsResult = TreeSitterLoader.parseFile(ts5, 'typescript');
    expect(tsResult).toBeDefined();
    expect(typeof tsResult.hasError).toBe('boolean');
  });

  it('detects language accurately from file extensions', () => {
    expect(TreeSitterLoader.detectLanguage('foo.js')).toBe('javascript');
    expect(TreeSitterLoader.detectLanguage('foo.mjs')).toBe('javascript');
    expect(TreeSitterLoader.detectLanguage('foo.cjs')).toBe('javascript');
    expect(TreeSitterLoader.detectLanguage('foo.jsx')).toBe('javascript');
    expect(TreeSitterLoader.detectLanguage('foo.ts')).toBe('typescript');
    expect(TreeSitterLoader.detectLanguage('foo.mts')).toBe('typescript');
    expect(TreeSitterLoader.detectLanguage('foo.cts')).toBe('typescript');
    expect(TreeSitterLoader.detectLanguage('foo.tsx')).toBe('tsx');
    expect(TreeSitterLoader.detectLanguage('foo.py')).toBe('python');
    expect(TreeSitterLoader.detectLanguage('foo.go')).toBe('go');
    expect(TreeSitterLoader.detectLanguage('foo.java')).toBe('java');
    expect(TreeSitterLoader.detectLanguage('foo.rs')).toBe('rust');
    expect(TreeSitterLoader.detectLanguage('foo.cs')).toBe('c_sharp');
    expect(TreeSitterLoader.detectLanguage('foo.unknown')).toBeNull();
  });

  it('returns valid wasm directory from getWasmDirectory()', () => {
    const dir = TreeSitterLoader.getWasmDirectory();
    expect(dir).toBeDefined();
    expect(dir.length).toBeGreaterThan(0);
  });

  it('calling init() multiple times is a clean idempotent no-op', async () => {
    await expect(TreeSitterLoader.init()).resolves.not.toThrow();
  });

  it('enforces parse timeout guard in parseFile', () => {
    const res = TreeSitterLoader.parseFile('const x = 1;', 'javascript', {
      parseTimeoutMs: -1,
    });
    expect(res.tree).toBeNull();
    expect(res.hasError).toBe(true);
    expect(res.errorReason).toContain('exceeded timeout limit');
  });

  it('handles unknown or unavailable languages in getParser and parseFile cleanly', () => {
    const p = TreeSitterLoader.getParser('unknown_lang' as unknown as SupportedLanguage);
    expect(p.error).toBeDefined();
    expect(p.error).toContain('is not loaded or unavailable');

    const parseRes = TreeSitterLoader.parseFile(
      'const x = 1;',
      'unknown_lang' as unknown as SupportedLanguage
    );
    expect(parseRes.tree).toBeNull();
    expect(parseRes.hasError).toBe(true);
    expect(parseRes.errorReason).toContain('is not loaded or unavailable');
  });

  it('parses empty content cleanly without crash', () => {
    const res = TreeSitterLoader.parseFile('', 'javascript');
    expect(res.tree).toBeDefined();
    expect(res.hasError).toBe(false);
  });
});
