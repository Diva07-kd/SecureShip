#!/usr/bin/env node
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync, execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../..');
const packageScript = path.resolve(__dirname, 'package-standalone.mjs');
const cliDistAssets = path.resolve(repoRoot, 'packages/cli/dist');

console.log('🧪 Running scripts/release/package-standalone.test.mjs (Layer C hermetic tests)...');

const tempDirs = [];
function makeTempDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function cleanup() {
  for (const d of tempDirs) {
    try {
      fs.rmSync(d, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

function extractArchive(archivePath, extractDest) {
  if (archivePath.endsWith('.zip')) {
    if (process.platform === 'win32') {
      const escArc = archivePath.replace(/'/g, "''");
      const escDst = extractDest.replace(/'/g, "''");
      execSync(
        `powershell -NoProfile -NonInteractive -Command "Expand-Archive -Path '${escArc}' -DestinationPath '${escDst}' -Force"`,
        { stdio: 'pipe' }
      );
    } else {
      execSync(`unzip -q "${archivePath}" -d "${extractDest}"`, { stdio: 'pipe' });
    }
  } else {
    execSync(`tar -xzf "${archivePath}" -C "${extractDest}"`, { stdio: 'pipe' });
  }
}

function getAllRelativeFiles(dir, base = dir) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...getAllRelativeFiles(fullPath, base));
    } else {
      results.push(path.relative(base, fullPath).replace(/\\/g, '/'));
    }
  }
  return results.sort();
}

function createValidAssetsFixture(destDir) {
  const assetsDir = path.join(destDir, 'assets');
  fs.mkdirSync(assetsDir, { recursive: true });

  const srcWasm = path.join(cliDistAssets, 'wasm');
  const dstWasm = path.join(assetsDir, 'wasm');
  fs.mkdirSync(dstWasm, { recursive: true });
  for (const f of fs.readdirSync(srcWasm).filter((x) => x.endsWith('.wasm'))) {
    fs.copyFileSync(path.join(srcWasm, f), path.join(dstWasm, f));
  }

  const srcData = path.join(cliDistAssets, 'data');
  const dstData = path.join(assetsDir, 'data');
  fs.mkdirSync(dstData, { recursive: true });
  for (const f of fs.readdirSync(srcData).filter((x) => x.endsWith('.json'))) {
    fs.copyFileSync(path.join(srcData, f), path.join(dstData, f));
  }

  const srcRules = path.join(cliDistAssets, 'rules/secureship-sast');
  const dstRules = path.join(assetsDir, 'rules/secureship-sast');
  fs.mkdirSync(dstRules, { recursive: true });
  for (const f of fs
    .readdirSync(srcRules)
    .filter((x) => x.endsWith('.yml') || x.endsWith('.yaml'))) {
    fs.copyFileSync(path.join(srcRules, f), path.join(dstRules, f));
  }

  fs.copyFileSync(
    path.join(cliDistAssets, 'tools.lock.json'),
    path.join(assetsDir, 'tools.lock.json')
  );

  const binDir = path.join(destDir, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  const binName = process.platform === 'win32' ? 'secureship.exe' : 'secureship';
  const binaryPath = path.join(binDir, binName);
  fs.writeFileSync(binaryPath, '#!/bin/sh\necho "secureship 1.0.0"\n');
  if (process.platform !== 'win32') {
    fs.chmodSync(binaryPath, 0o755);
  }

  return { assetsDir, binaryPath };
}

try {
  // Test C1: Happy path with space in path and deep layout equality
  console.log('Testing C1: Happy path packaging into path with space...');
  const fixtureRoot = makeTempDir('secureship c1 root space ');
  const outDir = makeTempDir('secureship c1 out space ');
  const { assetsDir, binaryPath } = createValidAssetsFixture(fixtureRoot);

  const target = process.platform === 'win32' ? 'win32-x64' : 'linux-x64';
  const isWin = target === 'win32-x64';
  const archiveExt = isWin ? 'zip' : 'tar.gz';
  const archiveName = `secureship-${target}.${archiveExt}`;

  const res1 = spawnSync(
    process.execPath,
    [
      packageScript,
      '--target',
      target,
      '--binary',
      binaryPath,
      '--assets',
      assetsDir,
      '--out',
      outDir,
    ],
    { encoding: 'utf-8' }
  );
  assert.equal(res1.status, 0, `Packaging failed: ${res1.stderr || res1.stdout}`);

  const archivePath = path.join(outDir, archiveName);
  const sha256Path = `${archivePath}.sha256`;
  assert.ok(fs.existsSync(archivePath), `Archive missing: ${archivePath}`);
  assert.ok(fs.existsSync(sha256Path), `Checksum missing: ${sha256Path}`);

  const actualSha = crypto
    .createHash('sha256')
    .update(fs.readFileSync(archivePath))
    .digest('hex')
    .toLowerCase();
  const fileSha = fs.readFileSync(sha256Path, 'utf-8').trim().toLowerCase();
  assert.equal(fileSha, actualSha, 'Checksum file mismatch');

  const extractDest = makeTempDir('secureship c1 extract space ');
  extractArchive(archivePath, extractDest);
  const topFolders = fs.readdirSync(extractDest);
  assert.deepEqual(
    topFolders,
    [`secureship-${target}`],
    'Did not extract to single top-level folder'
  );

  const files = getAllRelativeFiles(path.join(extractDest, `secureship-${target}`));
  const binName = isWin ? 'secureship.exe' : 'secureship';
  const expectedLayout = [
    'LICENSE',
    'README.md',
    'THIRD_PARTY_NOTICES.md',
    'data/vulnerable-symbols.json',
    'data/vulnerable-symbols.manifest.json',
    'rules/secureship-sast/secureship-js-child-process-exec.yml',
    'rules/secureship-sast/secureship-js-eval.yml',
    'rules/secureship-sast/secureship-js-hardcoded-jwt-secret.yml',
    'rules/secureship-sast/secureship-js-insecure-random.yml',
    'rules/secureship-sast/secureship-js-sql-concat.yml',
    'rules/secureship-sast/secureship-py-insecure-hash.yml',
    'rules/secureship-sast/secureship-py-pickle-load.yml',
    'rules/secureship-sast/secureship-py-sql-format.yml',
    'rules/secureship-sast/secureship-py-subprocess-shell.yml',
    'rules/secureship-sast/secureship-py-yaml-load.yml',
    binName,
    'tools.lock.json',
    'wasm/tree-sitter-c_sharp.wasm',
    'wasm/tree-sitter-go.wasm',
    'wasm/tree-sitter-java.wasm',
    'wasm/tree-sitter-javascript.wasm',
    'wasm/tree-sitter-python.wasm',
    'wasm/tree-sitter-rust.wasm',
    'wasm/tree-sitter-tsx.wasm',
    'wasm/tree-sitter-typescript.wasm',
    'wasm/tree-sitter.wasm',
  ].sort();

  assert.deepEqual(
    files,
    expectedLayout,
    'Extracted archive layout does not deep-equal expected DEV-4 layout'
  );
  console.log('✔ C1 PASSED (with deep structural layout check)');

  // Test C2: Target type
  console.log('Testing C2: Target archive type...');
  assert.ok(
    fs.existsSync(
      path.join(outDir, isWin ? `secureship-${target}.zip` : `secureship-${target}.tar.gz`)
    )
  );
  console.log('✔ C2 PASSED');

  // Test C3: Hermetic failure modes
  console.log('Testing C3: Failure cases...');

  // 1. Missing wasm
  {
    const c3Root = makeTempDir('secureship c3-wasm ');
    const c3Out = makeTempDir('secureship c3-wasm-out ');
    const c3Fixture = createValidAssetsFixture(c3Root);
    fs.rmSync(path.join(c3Fixture.assetsDir, 'wasm'), { recursive: true, force: true });
    const res = spawnSync(
      process.execPath,
      [
        packageScript,
        '--target',
        target,
        '--binary',
        c3Fixture.binaryPath,
        '--assets',
        c3Fixture.assetsDir,
        '--out',
        c3Out,
      ],
      { encoding: 'utf-8' }
    );
    assert.equal(res.status, 1, 'Should exit 1 on missing wasm');
    assert.ok(
      res.stderr.includes('Missing assets wasm directory'),
      `Expected error message not found: ${res.stderr}`
    );
  }

  // 2. wasm hash mismatch
  {
    const c3Root = makeTempDir('secureship c3-wasm-hash ');
    const c3Out = makeTempDir('secureship c3-wasm-hash-out ');
    const c3Fixture = createValidAssetsFixture(c3Root);
    fs.writeFileSync(
      path.join(c3Fixture.assetsDir, 'wasm', 'tree-sitter.wasm'),
      Buffer.from('TAMPERED_WASM')
    );
    const res = spawnSync(
      process.execPath,
      [
        packageScript,
        '--target',
        target,
        '--binary',
        c3Fixture.binaryPath,
        '--assets',
        c3Fixture.assetsDir,
        '--out',
        c3Out,
      ],
      { encoding: 'utf-8' }
    );
    assert.equal(res.status, 1, 'Should exit 1 on wasm hash mismatch');
    assert.ok(
      res.stderr.includes('failed manifest integrity') ||
        res.stderr.includes('Pre-archive verification failed'),
      `Expected error message not found: ${res.stderr}`
    );
  }

  // 3. missing data manifest
  {
    const c3Root = makeTempDir('secureship c3-manifest ');
    const c3Out = makeTempDir('secureship c3-manifest-out ');
    const c3Fixture = createValidAssetsFixture(c3Root);
    fs.rmSync(path.join(c3Fixture.assetsDir, 'data', 'vulnerable-symbols.manifest.json'));
    const res = spawnSync(
      process.execPath,
      [
        packageScript,
        '--target',
        target,
        '--binary',
        c3Fixture.binaryPath,
        '--assets',
        c3Fixture.assetsDir,
        '--out',
        c3Out,
      ],
      { encoding: 'utf-8' }
    );
    assert.equal(res.status, 1, 'Should exit 1 on missing data manifest');
    assert.ok(
      res.stderr.includes('missing vulnerable-symbols.json or manifest'),
      `Expected error message not found: ${res.stderr}`
    );
  }

  // 4. data hash mismatch
  {
    const c3Root = makeTempDir('secureship c3-data-hash ');
    const c3Out = makeTempDir('secureship c3-data-hash-out ');
    const c3Fixture = createValidAssetsFixture(c3Root);
    fs.writeFileSync(
      path.join(c3Fixture.assetsDir, 'data', 'vulnerable-symbols.json'),
      JSON.stringify({ tampered: true })
    );
    const res = spawnSync(
      process.execPath,
      [
        packageScript,
        '--target',
        target,
        '--binary',
        c3Fixture.binaryPath,
        '--assets',
        c3Fixture.assetsDir,
        '--out',
        c3Out,
      ],
      { encoding: 'utf-8' }
    );
    assert.equal(res.status, 1, 'Should exit 1 on data hash mismatch');
    assert.ok(
      res.stderr.includes('vulnerable-symbols.json SHA-256 mismatch'),
      `Expected error message not found: ${res.stderr}`
    );
  }

  // 5. empty rules dir
  {
    const c3Root = makeTempDir('secureship c3-rules ');
    const c3Out = makeTempDir('secureship c3-rules-out ');
    const c3Fixture = createValidAssetsFixture(c3Root);
    const rulesSubdir = path.join(c3Fixture.assetsDir, 'rules', 'secureship-sast');
    for (const f of fs.readdirSync(rulesSubdir)) {
      fs.rmSync(path.join(rulesSubdir, f));
    }
    const res = spawnSync(
      process.execPath,
      [
        packageScript,
        '--target',
        target,
        '--binary',
        c3Fixture.binaryPath,
        '--assets',
        c3Fixture.assetsDir,
        '--out',
        c3Out,
      ],
      { encoding: 'utf-8' }
    );
    assert.equal(res.status, 1, 'Should exit 1 on empty rules dir');
    assert.ok(
      res.stderr.includes('staged rules directory contains 0 YAML files'),
      `Expected error message not found: ${res.stderr}`
    );
  }

  // 6. missing binary
  {
    const c3Root = makeTempDir('secureship c3-bin-missing ');
    const c3Out = makeTempDir('secureship c3-bin-missing-out ');
    const c3Fixture = createValidAssetsFixture(c3Root);
    const nonExistentBin = path.join(c3Root, 'does-not-exist.bin');
    const res = spawnSync(
      process.execPath,
      [
        packageScript,
        '--target',
        target,
        '--binary',
        nonExistentBin,
        '--assets',
        c3Fixture.assetsDir,
        '--out',
        c3Out,
      ],
      { encoding: 'utf-8' }
    );
    assert.equal(res.status, 1, 'Should exit 1 on missing binary');
    assert.ok(
      res.stderr.includes('Binary not found at'),
      `Expected error message not found: ${res.stderr}`
    );
  }

  // 7. empty binary
  {
    const c3Root = makeTempDir('secureship c3-bin-empty ');
    const c3Out = makeTempDir('secureship c3-bin-empty-out ');
    const c3Fixture = createValidAssetsFixture(c3Root);
    const emptyBin = path.join(c3Root, 'empty.bin');
    fs.writeFileSync(emptyBin, '');
    const res = spawnSync(
      process.execPath,
      [
        packageScript,
        '--target',
        target,
        '--binary',
        emptyBin,
        '--assets',
        c3Fixture.assetsDir,
        '--out',
        c3Out,
      ],
      { encoding: 'utf-8' }
    );
    assert.equal(res.status, 1, 'Should exit 1 on empty binary');
    assert.ok(
      res.stderr.includes('Binary is empty at'),
      `Expected error message not found: ${res.stderr}`
    );
  }

  // 8. missing LICENSE / README.md / THIRD_PARTY_NOTICES.md
  for (const doc of ['LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.md']) {
    const docPath = path.join(repoRoot, doc);
    const docBackup = path.join(repoRoot, `${doc}.bak_pkg_test`);
    if (fs.existsSync(docPath)) {
      fs.renameSync(docPath, docBackup);
      try {
        const c3Root = makeTempDir(`secureship c3-${doc} `);
        const c3Out = makeTempDir(`secureship c3-${doc}-out `);
        const c3Fixture = createValidAssetsFixture(c3Root);
        const res = spawnSync(
          process.execPath,
          [
            packageScript,
            '--target',
            target,
            '--binary',
            c3Fixture.binaryPath,
            '--assets',
            c3Fixture.assetsDir,
            '--out',
            c3Out,
          ],
          { encoding: 'utf-8' }
        );
        assert.equal(res.status, 1, `Should exit 1 when ${doc} is missing`);
        assert.ok(
          res.stderr.includes(`Missing required root document:`) && res.stderr.includes(doc),
          `Expected missing root document error for ${doc}, got: ${res.stderr}`
        );
      } finally {
        fs.renameSync(docBackup, docPath);
      }
    }
  }

  console.log('✔ C3 PASSED (all 10 failure cases verified)');

  // Test C4: Idempotency
  console.log('Testing C4: Idempotency & stale stage removal...');
  const c4Root = makeTempDir('secureship c4 root ');
  const c4Out = makeTempDir('secureship c4 out ');
  const c4Fixture = createValidAssetsFixture(c4Root);
  const r1 = spawnSync(
    process.execPath,
    [
      packageScript,
      '--target',
      target,
      '--binary',
      c4Fixture.binaryPath,
      '--assets',
      c4Fixture.assetsDir,
      '--out',
      c4Out,
    ],
    { encoding: 'utf-8' }
  );
  assert.equal(r1.status, 0);

  // Plant stale file
  const stageFolder = path.join(c4Out, `secureship-${target}`);
  fs.writeFileSync(path.join(stageFolder, 'stale-test.tmp'), 'STALE');

  const r2 = spawnSync(
    process.execPath,
    [
      packageScript,
      '--target',
      target,
      '--binary',
      c4Fixture.binaryPath,
      '--assets',
      c4Fixture.assetsDir,
      '--out',
      c4Out,
    ],
    { encoding: 'utf-8' }
  );
  assert.equal(r2.status, 0);
  assert.ok(!fs.existsSync(path.join(stageFolder, 'stale-test.tmp')), 'Stale file was not removed');
  console.log('✔ C4 PASSED');

  // Test C5: Non-allow-listed files
  console.log('Testing C5: Allowlist file filtering...');
  const c5Root = makeTempDir('secureship c5 root ');
  const c5Out = makeTempDir('secureship c5 out ');
  const c5Fixture = createValidAssetsFixture(c5Root);

  fs.writeFileSync(path.join(c5Fixture.assetsDir, 'data', 'README.md'), 'docs');
  fs.writeFileSync(
    path.join(c5Fixture.assetsDir, 'rules', 'secureship-sast', 'notes.txt'),
    'notes'
  );

  const r5 = spawnSync(
    process.execPath,
    [
      packageScript,
      '--target',
      target,
      '--binary',
      c5Fixture.binaryPath,
      '--assets',
      c5Fixture.assetsDir,
      '--out',
      c5Out,
    ],
    { encoding: 'utf-8' }
  );
  assert.equal(r5.status, 0);

  const c5Extract = makeTempDir('secureship c5 extract ');
  extractArchive(path.join(c5Out, archiveName), c5Extract);
  const c5Files = getAllRelativeFiles(path.join(c5Extract, `secureship-${target}`));
  assert.ok(!c5Files.includes('data/README.md'), 'data/README.md should not be packaged');
  assert.ok(
    !c5Files.includes('rules/secureship-sast/notes.txt'),
    'rules/notes.txt should not be packaged'
  );
  console.log('✔ C5 PASSED');

  console.log('\n🎉 ALL LAYER C TESTS PASSED!\n');
  process.exit(0);
} catch (err) {
  console.error('\n❌ LAYER C TEST FAILED:', err);
  process.exit(1);
} finally {
  cleanup();
}
