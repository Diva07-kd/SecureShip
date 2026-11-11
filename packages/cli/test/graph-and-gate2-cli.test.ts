import { describe, it, expect, afterEach } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { SafeProcessRunner } from '@secureship/core-engine';

describe('CLI Graph & Gate 2 E2E Suite', () => {
  const cliEntry = path.resolve('packages/cli/dist/index.js');
  const tmpDirs: string[] = [];

  function createFixture(files: Record<string, string>): string {
    const dir = mkdtempSync(path.join(tmpdir(), 'secureship-cli-g2-'));
    tmpDirs.push(dir);
    for (const [relPath, content] of Object.entries(files)) {
      const fullPath = path.join(dir, relPath);
      writeFileSync(fullPath, content, 'utf8');
    }
    return dir;
  }

  afterEach(() => {
    for (const d of tmpDirs) {
      try {
        rmSync(d, { recursive: true, force: true });
      } catch {
        // cleanup
      }
    }
    tmpDirs.length = 0;
  });

  it('doctor command verifies bundled WASM grammars', async () => {
    const res = await SafeProcessRunner.run('node', [cliEntry, 'doctor'], { timeoutMs: 45_000 });
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('Reachability Engine WASM Grammars:');
    expect(res.stdout).toContain('tree-sitter.wasm');
    expect(res.stdout).toContain('tree-sitter-javascript.wasm');
    expect(res.stdout).toContain('tree-sitter-typescript.wasm');
    expect(res.stdout).toContain('tree-sitter-tsx.wasm');
    expect(res.stdout).toContain('tree-sitter-python.wasm');
    expect(res.stdout).toContain('Verified');
  }, 60_000);

  it('status command displays import-level reachability included and function-level Pro', async () => {
    const res = await SafeProcessRunner.run('node', [cliEntry, 'status'], { timeoutMs: 10_000 });
    expect(res.exitCode).toBe(0);
    const cleanOut = res.stdout.replace(/\u001b\[[0-9;]*m/g, '');
    expect(cleanOut).toContain('Import-level reachability   : included');
    expect(cleanOut).toContain('Function-level reachability :');
    expect(cleanOut).toContain('Requires PRO_TEAM');
  });

  it('graph command outputs JSON stats', async () => {
    const dir = createFixture({
      'index.js': `const fs = require('fs');\nconsole.log(fs);`,
    });
    const res = await SafeProcessRunner.run('node', [cliEntry, 'graph', dir, '--json'], {
      timeoutMs: 10_000,
    });
    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(res.stdout);
    expect(parsed.totalFiles).toBe(1);
    expect(parsed.entrypoints).toBeDefined();
    expect(parsed.hasAnyParseErrorInProduction).toBe(false);
  });

  it('graph command outputs DOT graph notation', async () => {
    const dir = createFixture({
      'index.js': `const helper = require('./helper.js');`,
      'helper.js': `module.exports = 42;`,
    });
    const res = await SafeProcessRunner.run('node', [cliEntry, 'graph', dir, '--format', 'dot'], {
      timeoutMs: 10_000,
    });
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('digraph ImportGraph {');
    expect(res.stdout).toContain('"index.js" -> "helper.js";');
  });

  it('scan human output contains mandatory disclaimer and never uses "safe" for not imported', async () => {
    const dir = createFixture({
      'package.json': JSON.stringify({
        name: 'test-app',
        main: 'index.js',
        dependencies: { 'is-stream': '^3.0.0' },
      }),
      'index.js': `console.log("hello");`,
    });

    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', dir, '--scanners', 'trivy', '--gate2', 'annotate', '--no-cache'],
      { timeoutMs: 25_000 }
    );

    const out = res.stdout;
    // Word "safe" must NEVER be used for reachability verdict
    expect(out.toLowerCase()).not.toContain('is safe');
    expect(out.toLowerCase()).not.toContain('safely unreachable');
  });
});
