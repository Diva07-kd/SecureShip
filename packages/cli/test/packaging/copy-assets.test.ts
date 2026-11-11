import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../../..');
const realCopyScriptPath = path.resolve(repoRoot, 'scripts/copy-wasm.mjs');

interface FakeTreeOptions {
  includeWasm?: boolean;
  includeData?: boolean;
  includeRules?: boolean;
  includeToolsLock?: boolean;
  corruptManifestHash?: boolean;
  emptyRules?: boolean;
  addNonAllowlistedFiles?: boolean;
}

describe('Layer D - copy-wasm.mjs Hermetic Asset Packaging Suite (DEV-2 / F-PKG-001)', () => {
  const tempDirs: string[] = [];

  function makeTempDir(prefix: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  afterEach(() => {
    for (const d of tempDirs) {
      try {
        fs.rmSync(d, { recursive: true, force: true });
      } catch {
        // cleanup ignore
      }
    }
    tempDirs.length = 0;
  });

  function setupFakeTree(
    fakeRoot: string,
    options: FakeTreeOptions = {}
  ): {
    scriptPath: string;
    wasmSrcDir: string;
    dataSrcDir: string;
    rulesSrcDir: string;
    distDir: string;
  } {
    const {
      includeWasm = true,
      includeData = true,
      includeRules = true,
      includeToolsLock = true,
      corruptManifestHash = false,
      emptyRules = false,
      addNonAllowlistedFiles = false,
    } = options;

    // 1. Copy script into <fakeRoot>/scripts/copy-wasm.mjs
    const scriptsDir = path.join(fakeRoot, 'scripts');
    fs.mkdirSync(scriptsDir, { recursive: true });
    const scriptPath = path.join(scriptsDir, 'copy-wasm.mjs');
    fs.copyFileSync(realCopyScriptPath, scriptPath);

    // 2. Prepare destination packages/cli/dist
    const distDir = path.join(fakeRoot, 'packages', 'cli', 'dist');
    fs.mkdirSync(distDir, { recursive: true });

    // 3. tools.lock.json
    if (includeToolsLock) {
      const lockContent = JSON.stringify({ version: '1.0', tools: { opengrep: '1.31.0' } });
      fs.writeFileSync(path.join(fakeRoot, 'tools.lock.json'), lockContent, 'utf-8');
    }

    // 4. packages/reachability/wasm
    const wasmSrcDir = path.join(fakeRoot, 'packages', 'reachability', 'wasm');
    if (includeWasm) {
      fs.mkdirSync(wasmSrcDir, { recursive: true });
      fs.writeFileSync(path.join(wasmSrcDir, 'tree-sitter.wasm'), Buffer.from('mock-wasm-1'));
      fs.writeFileSync(
        path.join(wasmSrcDir, 'tree-sitter-javascript.wasm'),
        Buffer.from('mock-wasm-2')
      );
    }

    // 5. packages/reachability/data
    const dataSrcDir = path.join(fakeRoot, 'packages', 'reachability', 'data');
    if (includeData) {
      fs.mkdirSync(dataSrcDir, { recursive: true });
      const rawData = JSON.stringify({ version: '1.0', datasetId: 'test', entries: [] }, null, 2);
      const actualHash = crypto
        .createHash('sha256')
        .update(Buffer.from(rawData, 'utf-8'))
        .digest('hex');
      const manifestHash = corruptManifestHash
        ? '0000000000000000000000000000000000000000000000000000000000000000'
        : actualHash;

      const manifestContent = JSON.stringify(
        {
          version: '1.0',
          datasetId: 'test',
          sha256: manifestHash,
          entryCount: 0,
        },
        null,
        2
      );

      fs.writeFileSync(path.join(dataSrcDir, 'vulnerable-symbols.json'), rawData, 'utf-8');
      fs.writeFileSync(
        path.join(dataSrcDir, 'vulnerable-symbols.manifest.json'),
        manifestContent,
        'utf-8'
      );

      if (addNonAllowlistedFiles) {
        fs.writeFileSync(path.join(dataSrcDir, 'README.md'), '# Data readme', 'utf-8');
        fs.writeFileSync(path.join(dataSrcDir, 'notes.txt'), 'notes', 'utf-8');
        fs.writeFileSync(
          path.join(dataSrcDir, 'helper.js'),
          'console.log("not allowed");',
          'utf-8'
        );
      }
    }

    // 6. rules/secureship-sast
    const rulesSrcDir = path.join(fakeRoot, 'rules', 'secureship-sast');
    if (includeRules) {
      fs.mkdirSync(rulesSrcDir, { recursive: true });
      if (!emptyRules) {
        fs.writeFileSync(
          path.join(rulesSrcDir, 'secureship-js-eval.yml'),
          'id: secureship-js-eval\nmessage: eval detected\n',
          'utf-8'
        );
        const subRulesDir = path.join(rulesSrcDir, 'nested-category');
        fs.mkdirSync(subRulesDir, { recursive: true });
        fs.writeFileSync(
          path.join(subRulesDir, 'secureship-py-sql.yaml'),
          'id: secureship-py-sql\nmessage: sql detected\n',
          'utf-8'
        );
      }

      if (addNonAllowlistedFiles) {
        fs.writeFileSync(path.join(rulesSrcDir, 'RULE_SPEC.md'), '# Spec', 'utf-8');
        fs.writeFileSync(path.join(rulesSrcDir, 'license.txt'), 'MIT', 'utf-8');
        fs.writeFileSync(path.join(rulesSrcDir, 'validator.js'), 'export default {};', 'utf-8');
      }
    }

    return { scriptPath, wasmSrcDir, dataSrcDir, rulesSrcDir, distDir };
  }

  function getTreeHash(dir: string): Record<string, string> {
    const hashes: Record<string, string> = {};
    function scan(d: string) {
      if (!fs.existsSync(d)) return;
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, entry.name);
        if (entry.isDirectory()) {
          scan(full);
        } else {
          const rel = path.relative(dir, full).replace(/\\/g, '/');
          const hash = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
          hashes[rel] = hash;
        }
      }
    }
    scan(dir);
    return hashes;
  }

  it('D1: happy path with space in root path: exit 0, dist/data has 2 files, dist/rules preserved, byte-identical to sources', () => {
    const fakeRoot = makeTempDir('secureship copy space test ');
    const { scriptPath, distDir, dataSrcDir, rulesSrcDir } = setupFakeTree(fakeRoot);

    const proc = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });

    expect(proc.status).toEqual(0);

    // dist/data has exactly 2 files
    const dataFiles = fs.readdirSync(path.join(distDir, 'data')).sort();
    expect(dataFiles).toEqual(['vulnerable-symbols.json', 'vulnerable-symbols.manifest.json']);

    // Byte-identical check for data
    const srcData = fs.readFileSync(path.join(dataSrcDir, 'vulnerable-symbols.json'));
    const destData = fs.readFileSync(path.join(distDir, 'data', 'vulnerable-symbols.json'));
    expect(Buffer.compare(srcData, destData)).toEqual(0);

    // dist/rules nested structure preserved
    expect(
      fs.existsSync(path.join(distDir, 'rules', 'secureship-sast', 'secureship-js-eval.yml'))
    ).toEqual(true);
    expect(
      fs.existsSync(
        path.join(distDir, 'rules', 'secureship-sast', 'nested-category', 'secureship-py-sql.yaml')
      )
    ).toEqual(true);

    const srcPyRule = fs.readFileSync(
      path.join(rulesSrcDir, 'nested-category', 'secureship-py-sql.yaml')
    );
    const destPyRule = fs.readFileSync(
      path.join(distDir, 'rules', 'secureship-sast', 'nested-category', 'secureship-py-sql.yaml')
    );
    expect(Buffer.compare(srcPyRule, destPyRule)).toEqual(0);

    // wasm + tools.lock.json copied
    expect(fs.existsSync(path.join(distDir, 'wasm', 'tree-sitter.wasm'))).toEqual(true);
    expect(fs.existsSync(path.join(distDir, 'wasm', 'tree-sitter-javascript.wasm'))).toEqual(true);
    expect(fs.existsSync(path.join(distDir, 'tools.lock.json'))).toEqual(true);
  });

  it('D2: missing data/ directory causes exit 1 and stderr explicitly names the path', () => {
    const fakeRoot = makeTempDir('secureship-missing-data-');
    const { scriptPath, dataSrcDir } = setupFakeTree(fakeRoot, { includeData: false });

    const proc = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });

    expect(proc.status).toEqual(1);
    expect(proc.stderr).toContain('Source directory does not exist');
    expect(proc.stderr).toContain(dataSrcDir);
  });

  it('D3: missing rules/ directory causes exit 1 and stderr explicitly names the path', () => {
    const fakeRoot = makeTempDir('secureship-missing-rules-');
    const { scriptPath, rulesSrcDir } = setupFakeTree(fakeRoot, { includeRules: false });

    const proc = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });

    expect(proc.status).toEqual(1);
    expect(proc.stderr).toContain('Source directory does not exist');
    expect(proc.stderr).toContain(rulesSrcDir);
  });

  it('D4: missing wasm/ directory causes exit 1 and regression error message in stderr', () => {
    const fakeRoot = makeTempDir('secureship-missing-wasm-');
    const { scriptPath, wasmSrcDir } = setupFakeTree(fakeRoot, { includeWasm: false });

    const proc = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });

    expect(proc.status).toEqual(1);
    expect(proc.stderr).toContain('Source WASM directory does not exist:');
    expect(proc.stderr).toContain(wasmSrcDir);
  });

  it('D5: manifest sha256 mismatch causes self-verification failure and exit 1', () => {
    const fakeRoot = makeTempDir('secureship-tampered-manifest-');
    const { scriptPath } = setupFakeTree(fakeRoot, { corruptManifestHash: true });

    const proc = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });

    expect(proc.status).toEqual(1);
    expect(proc.stderr).toContain('Self-verification failed: SHA-256 mismatch');
  });

  it('D6: empty rules directory (zero YAML) causes self-verification failure and exit 1', () => {
    const fakeRoot = makeTempDir('secureship-empty-rules-');
    const { scriptPath } = setupFakeTree(fakeRoot, { emptyRules: true });

    const proc = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });

    expect(proc.status).toEqual(1);
    expect(proc.stderr).toContain(
      'Self-verification failed: dist/rules/secureship-sast contains no YAML files'
    );
  });

  it('D7: non-allowlisted files (.md, .txt, .js) in data/ and rules/ are filtered out and NOT copied', () => {
    const fakeRoot = makeTempDir('secureship-filter-assets-');
    const { scriptPath, distDir } = setupFakeTree(fakeRoot, { addNonAllowlistedFiles: true });

    const proc = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });
    expect(proc.status).toEqual(0);

    const distDataFiles = fs.readdirSync(path.join(distDir, 'data')).sort();
    expect(distDataFiles).toEqual(['vulnerable-symbols.json', 'vulnerable-symbols.manifest.json']);
    expect(distDataFiles.includes('README.md')).toEqual(false);
    expect(distDataFiles.includes('notes.txt')).toEqual(false);
    expect(distDataFiles.includes('helper.js')).toEqual(false);

    const distRulesFiles = fs.readdirSync(path.join(distDir, 'rules', 'secureship-sast')).sort();
    expect(distRulesFiles.includes('RULE_SPEC.md')).toEqual(false);
    expect(distRulesFiles.includes('license.txt')).toEqual(false);
    expect(distRulesFiles.includes('validator.js')).toEqual(false);
  });

  it('D8: idempotent: running twice produces identical dist tree hash', () => {
    const fakeRoot = makeTempDir('secureship-idempotent-');
    const { scriptPath, distDir } = setupFakeTree(fakeRoot);

    const run1 = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });
    expect(run1.status).toEqual(0);
    const hashes1 = getTreeHash(distDir);

    const run2 = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });
    expect(run2.status).toEqual(0);
    const hashes2 = getTreeHash(distDir);

    expect(hashes1).toEqual(hashes2);
  });

  it('D9: stale file planted in dist/rules/secureship-sast/zzz-stale.yaml is purged upon rerun', () => {
    const fakeRoot = makeTempDir('secureship-purge-stale-');
    const { scriptPath, distDir } = setupFakeTree(fakeRoot);

    // Run 1: initial population
    const run1 = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });
    expect(run1.status).toEqual(0);

    // Plant a stale file in dist/rules/secureship-sast/
    const staleFile = path.join(distDir, 'rules', 'secureship-sast', 'zzz-stale.yaml');
    fs.writeFileSync(staleFile, 'stale: true\n', 'utf-8');
    expect(fs.existsSync(staleFile)).toEqual(true);

    // Run 2: script execution must clean out stale files
    const run2 = spawnSync(process.execPath, [scriptPath], { encoding: 'utf-8' });
    expect(run2.status).toEqual(0);

    expect(fs.existsSync(staleFile)).toEqual(false);
  });
});
