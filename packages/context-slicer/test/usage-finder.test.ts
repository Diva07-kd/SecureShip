import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { UsageFinder } from '../src/usage-finder.js';

describe('UsageFinder', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-usage-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('returns empty array if symbolName is missing, too short, or all digits', () => {
    expect(UsageFinder.findUsageSites(tmpDir, '', 'src/index.ts')).toEqual([]);
    expect(UsageFinder.findUsageSites(tmpDir, 'ab', 'src/index.ts')).toEqual([]);
    expect(UsageFinder.findUsageSites(tmpDir, '12345', 'src/index.ts')).toEqual([]);
  });

  it('discovers usage sites across files and redacts secrets', () => {
    const srcDir = path.join(tmpDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    const sourceFile = path.join(srcDir, 'source.ts');
    fs.writeFileSync(sourceFile, 'export function targetFunction() { return 1; }\n');

    const dummyStripe = 'sk_' + 'live_1234567890abcdef1234567890abcdef';
    const callerFile1 = path.join(srcDir, 'caller1.ts');
    fs.writeFileSync(
      callerFile1,
      'import { targetFunction } from "./source.js";\n' +
        `const apiKey = "${dummyStripe}";\n` +
        'const res = targetFunction();\n' +
        'console.log(res);\n'
    );

    const callerFile2 = path.join(srcDir, 'caller2.ts');
    fs.writeFileSync(
      callerFile2,
      '// File 2\n' + 'function test() {\n' + '  targetFunction();\n' + '}\n'
    );

    const results = UsageFinder.findUsageSites(tmpDir, 'targetFunction', sourceFile);
    expect(results.length).toBe(3);

    const caller1Result = results.find((r) => r.filePath.includes('caller1.ts'));
    expect(caller1Result).toBeDefined();
    // Secret must be redacted
    expect(caller1Result?.snippet).toContain('sk_live...[REDACTED]');
    expect(caller1Result?.snippet).not.toContain('sk_' + 'live_1234567890abcdef');
    expect(caller1Result?.startLine).toBeGreaterThanOrEqual(1);

    const caller2Result = results.find((r) => r.filePath.includes('caller2.ts'));
    expect(caller2Result).toBeDefined();
    expect(caller2Result?.snippet).toContain('targetFunction()');
  });

  it('skips source file itself, denylisted files, and binary files', () => {
    const srcDir = path.join(tmpDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    const sourceFile = path.join(srcDir, 'source.ts');
    fs.writeFileSync(sourceFile, 'function mySymbol() {}\nmySymbol();\n');

    // Denylisted file (.env)
    const envFile = path.join(tmpDir, '.env');
    fs.writeFileSync(envFile, 'VAR=mySymbol\n');

    // Binary file extension (.png)
    const pngFile = path.join(srcDir, 'icon.png');
    fs.writeFileSync(pngFile, 'fake png containing mySymbol');

    // Binary buffer (contains null byte)
    const binFile = path.join(srcDir, 'data.txt');
    const binBuf = Buffer.alloc(20);
    binBuf.write('mySymbol', 0);
    binBuf[15] = 0; // null byte
    fs.writeFileSync(binFile, binBuf);

    // Ignored directories (node_modules, .git, dist, build)
    const nodeModulesDir = path.join(tmpDir, 'node_modules', 'pkg');
    fs.mkdirSync(nodeModulesDir, { recursive: true });
    fs.writeFileSync(path.join(nodeModulesDir, 'index.js'), 'mySymbol();\n');

    const results = UsageFinder.findUsageSites(tmpDir, 'mySymbol', sourceFile);
    expect(results).toEqual([]);
  });

  it('respects MAX_USAGE_SITES limit of 3', () => {
    const srcDir = path.join(tmpDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    const sourceFile = path.join(srcDir, 'source.ts');
    fs.writeFileSync(sourceFile, 'function popular() {}\n');

    for (let i = 1; i <= 5; i++) {
      fs.writeFileSync(path.join(srcDir, `file${i}.ts`), `// usage ${i}\npopular();\n`);
    }

    const results = UsageFinder.findUsageSites(tmpDir, 'popular', sourceFile);
    expect(results.length).toBe(3);
  });

  it('handles regex special characters in symbol name safely', () => {
    const srcDir = path.join(tmpDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    const sourceFile = path.join(srcDir, 'source.ts');
    fs.writeFileSync(sourceFile, 'const my$var = 1;\n');

    const usageFile = path.join(srcDir, 'usage.ts');
    fs.writeFileSync(usageFile, 'console.log(my$var);\n');

    const results = UsageFinder.findUsageSites(tmpDir, 'my$var', sourceFile);
    expect(results.length).toBe(1);
    expect(results[0]?.snippet).toContain('console.log(my$var)');
  });
});
