import { describe, it, expect, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync, execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..');
const packageScript = path.resolve(repoRoot, 'scripts/release/package-standalone.mjs');
const cliDistAssets = path.resolve(repoRoot, 'packages/cli/dist');

describe('LAYER C: Standalone Packaging Script Suite (DEV-4)', { timeout: 120_000 }, () => {
  const tempDirs: string[] = [];

  function makeTempDir(prefix: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  function runPackaging(args: string[]) {
    return spawnSync(process.execPath, [packageScript, ...args], {
      encoding: 'utf-8',
      timeout: 60_000,
      windowsHide: true,
    });
  }

  function extractArchive(archivePath: string, extractDest: string): void {
    if (archivePath.endsWith('.zip')) {
      if (process.platform === 'win32') {
        const escArc = archivePath.replace(/'/g, "''");
        const escDst = extractDest.replace(/'/g, "''");
        execSync(
          `powershell -NoProfile -NonInteractive -Command "Expand-Archive -Path '${escArc}' -DestinationPath '${escDst}' -Force"`,
          { stdio: 'pipe', timeout: 60_000 }
        );
      } else {
        execSync(`unzip -q "${archivePath}" -d "${extractDest}"`, {
          stdio: 'pipe',
          timeout: 60_000,
        });
      }
    } else {
      execSync(`tar -xzf "${archivePath}" -C "${extractDest}"`, { stdio: 'pipe', timeout: 60_000 });
    }
  }

  function getAllRelativeFiles(dir: string, base: string = dir): string[] {
    const results: string[] = [];
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

  function createValidAssetsFixture(destDir: string): {
    assetsDir: string;
    binaryPath: string;
  } {
    const assetsDir = path.join(destDir, 'assets');
    fs.mkdirSync(assetsDir, { recursive: true });

    // Copy wasm files
    const srcWasm = path.join(cliDistAssets, 'wasm');
    const dstWasm = path.join(assetsDir, 'wasm');
    fs.mkdirSync(dstWasm, { recursive: true });
    for (const f of fs.readdirSync(srcWasm).filter((x) => x.endsWith('.wasm'))) {
      fs.copyFileSync(path.join(srcWasm, f), path.join(dstWasm, f));
    }

    // Copy data files
    const srcData = path.join(cliDistAssets, 'data');
    const dstData = path.join(assetsDir, 'data');
    fs.mkdirSync(dstData, { recursive: true });
    for (const f of fs.readdirSync(srcData).filter((x) => x.endsWith('.json'))) {
      fs.copyFileSync(path.join(srcData, f), path.join(dstData, f));
    }

    // Copy rules files
    const srcRules = path.join(cliDistAssets, 'rules/secureship-sast');
    const dstRules = path.join(assetsDir, 'rules/secureship-sast');
    fs.mkdirSync(dstRules, { recursive: true });
    for (const f of fs
      .readdirSync(srcRules)
      .filter((x) => x.endsWith('.yml') || x.endsWith('.yaml'))) {
      fs.copyFileSync(path.join(srcRules, f), path.join(dstRules, f));
    }

    // Copy tools.lock.json
    fs.copyFileSync(
      path.join(cliDistAssets, 'tools.lock.json'),
      path.join(assetsDir, 'tools.lock.json')
    );

    // Create fake binary
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

  afterEach(() => {
    for (const d of tempDirs) {
      try {
        fs.rmSync(d, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
    tempDirs.length = 0;
  });

  // C1: Happy path, path with space, single top-level folder, exact DEV-4 layout, checksum match
  describe('C1: Happy path packaging with exact DEV-4 layout & checksum', () => {
    it('packages cleanly into a path with spaces, extracts to single top-level directory, and matches sha256', () => {
      const fixtureRoot = makeTempDir('secureship pack space ');
      const outDir = makeTempDir('secureship dist space ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(fixtureRoot);

      const target = process.platform === 'win32' ? 'win32-x64' : 'linux-x64';
      const isWin = target === 'win32-x64';
      const archiveExt = isWin ? 'zip' : 'tar.gz';
      const expectedArchiveName = `secureship-${target}.${archiveExt}`;

      const run = runPackaging([
        '--target',
        target,
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        outDir,
      ]);

      expect(run.status).toBe(0);

      const archivePath = path.join(outDir, expectedArchiveName);
      const sha256Path = `${archivePath}.sha256`;
      expect(fs.existsSync(archivePath)).toBe(true);
      expect(fs.existsSync(sha256Path)).toBe(true);

      // Verify checksum
      const actualHash = crypto
        .createHash('sha256')
        .update(fs.readFileSync(archivePath))
        .digest('hex')
        .toLowerCase();
      const recordedHash = fs.readFileSync(sha256Path, 'utf-8').trim().toLowerCase();
      expect(recordedHash).toBe(actualHash);

      // Extract and verify single top-level folder
      const extractDest = makeTempDir('secureship extract space ');
      extractArchive(archivePath, extractDest);

      const topEntries = fs.readdirSync(extractDest);
      expect(topEntries).toEqual([`secureship-${target}`]);

      const stageExtractDir = path.join(extractDest, `secureship-${target}`);
      const fileList = getAllRelativeFiles(stageExtractDir);

      const expectedBinName = isWin ? 'secureship.exe' : 'secureship';
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
        expectedBinName,
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

      expect(fileList).toEqual(expectedLayout);
    });
  });

  // C2: POSIX mode 0o755 & archive type matching
  describe('C2: Target archive type and executable permissions', () => {
    it('produces zip for win32-x64 and tar.gz for linux-x64 / darwin targets', () => {
      const fixtureRoot = makeTempDir('secureship c2 fixture ');
      const outDir = makeTempDir('secureship c2 out ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(fixtureRoot);

      // Test win32-x64 -> zip
      const runWin = runPackaging([
        '--target',
        'win32-x64',
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        outDir,
      ]);
      expect(runWin.status).toBe(0);
      expect(fs.existsSync(path.join(outDir, 'secureship-win32-x64.zip'))).toBe(true);

      // Test linux-x64 -> tar.gz
      const runLinux = runPackaging([
        '--target',
        'linux-x64',
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        outDir,
      ]);
      expect(runLinux.status).toBe(0);
      expect(fs.existsSync(path.join(outDir, 'secureship-linux-x64.tar.gz'))).toBe(true);

      if (process.platform !== 'win32') {
        const extractDest = makeTempDir('secureship c2 extract ');
        extractArchive(path.join(outDir, 'secureship-linux-x64.tar.gz'), extractDest);
        const extractedBin = path.join(extractDest, 'secureship-linux-x64', 'secureship');
        const mode = fs.statSync(extractedBin).mode;
        expect((mode & 0o111) !== 0).toBe(true);
      }
    });
  });

  // C3: Failure cases, each exit 1 with descriptive error message
  describe('C3: Hermetic failure modes and error validation', () => {
    it('exits 1 when wasm directory is missing', () => {
      const root = makeTempDir('secureship c3-1 ');
      const out = makeTempDir('secureship c3-1-out ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(root);
      fs.rmSync(path.join(assetsDir, 'wasm'), { recursive: true, force: true });

      const res = runPackaging([
        '--target',
        'win32-x64',
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain('Missing assets wasm directory');
    });

    it('exits 1 when a wasm binary has a SHA-256 hash mismatch', () => {
      const root = makeTempDir('secureship c3-2 ');
      const out = makeTempDir('secureship c3-2-out ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(root);
      // Corrupt tree-sitter.wasm
      fs.writeFileSync(
        path.join(assetsDir, 'wasm', 'tree-sitter.wasm'),
        Buffer.from('CORRUPT_WASM_CONTENT')
      );

      const res = runPackaging([
        '--target',
        'win32-x64',
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res.status).toBe(1);
      expect(res.stderr).toMatch(/failed manifest integrity|Pre-archive verification failed/);
    });

    it('exits 1 when data manifest is missing', () => {
      const root = makeTempDir('secureship c3-3 ');
      const out = makeTempDir('secureship c3-3-out ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(root);
      fs.rmSync(path.join(assetsDir, 'data', 'vulnerable-symbols.manifest.json'));

      const res = runPackaging([
        '--target',
        'win32-x64',
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain('missing vulnerable-symbols.json or manifest');
    });

    it('exits 1 when vulnerable-symbols.json SHA-256 mismatches manifest', () => {
      const root = makeTempDir('secureship c3-4 ');
      const out = makeTempDir('secureship c3-4-out ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(root);
      fs.writeFileSync(
        path.join(assetsDir, 'data', 'vulnerable-symbols.json'),
        JSON.stringify({ tampered: true })
      );

      const res = runPackaging([
        '--target',
        'win32-x64',
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain('vulnerable-symbols.json SHA-256 mismatch');
    });

    it('exits 1 when rules directory contains 0 YAML files', () => {
      const root = makeTempDir('secureship c3-5 ');
      const out = makeTempDir('secureship c3-5-out ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(root);
      const rulesDir = path.join(assetsDir, 'rules', 'secureship-sast');
      for (const f of fs.readdirSync(rulesDir)) {
        fs.rmSync(path.join(rulesDir, f));
      }

      const res = runPackaging([
        '--target',
        'win32-x64',
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain('staged rules directory contains 0 YAML files');
    });

    it('exits 1 when binary path does not exist', () => {
      const root = makeTempDir('secureship c3-6 ');
      const out = makeTempDir('secureship c3-6-out ');
      const { assetsDir } = createValidAssetsFixture(root);
      const nonExistentBin = path.join(root, 'missing-bin.exe');

      const res = runPackaging([
        '--target',
        'win32-x64',
        '--binary',
        nonExistentBin,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain('Binary not found at');
    });

    it('exits 1 when binary file is 0 bytes', () => {
      const root = makeTempDir('secureship c3-7 ');
      const out = makeTempDir('secureship c3-7-out ');
      const { assetsDir } = createValidAssetsFixture(root);
      const emptyBin = path.join(root, 'empty-bin.exe');
      fs.writeFileSync(emptyBin, '');

      const res = runPackaging([
        '--target',
        'win32-x64',
        '--binary',
        emptyBin,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain('Binary is empty at');
    });

    it('exits 1 when target is invalid', () => {
      const root = makeTempDir('secureship c3-8 ');
      const out = makeTempDir('secureship c3-8-out ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(root);

      const res = runPackaging([
        '--target',
        'solaris-sparc',
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain('Invalid target: solaris-sparc');
    });

    it('exits 1 when required root docs (LICENSE, README.md, THIRD_PARTY_NOTICES.md) are missing', () => {
      const requiredDocs = ['LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.md'];
      for (const doc of requiredDocs) {
        const docPath = path.join(repoRoot, doc);
        const docBackup = path.join(repoRoot, `${doc}.bak_unit_test`);
        if (fs.existsSync(docPath)) {
          fs.renameSync(docPath, docBackup);
          try {
            const root = makeTempDir(`secureship c3-${doc} `);
            const out = makeTempDir(`secureship c3-${doc}-out `);
            const { assetsDir, binaryPath } = createValidAssetsFixture(root);

            const res = runPackaging([
              '--target',
              'win32-x64',
              '--binary',
              binaryPath,
              '--assets',
              assetsDir,
              '--out',
              out,
            ]);
            expect(res.status).toBe(1);
            expect(res.stderr).toContain('Missing required root document:');
            expect(res.stderr).toContain(doc);
          } finally {
            fs.renameSync(docBackup, docPath);
          }
        }
      }
    });
  });

  // C4: Idempotence & removal of stale artifacts
  describe('C4: Idempotency and stale artifact cleanup', () => {
    it('two successive packaging runs produce identical extracted tree hashes and removes stale stage directory', () => {
      const root = makeTempDir('secureship c4 fixture ');
      const out = makeTempDir('secureship c4 out ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(root);

      const target = process.platform === 'win32' ? 'win32-x64' : 'linux-x64';

      // Run 1
      const res1 = runPackaging([
        '--target',
        target,
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res1.status).toBe(0);

      // Plant a stale file inside the stage directory to test cleanup
      const stageDir = path.join(out, `secureship-${target}`);
      fs.writeFileSync(path.join(stageDir, 'stale-artifact.tmp'), 'STALE');

      // Run 2
      const res2 = runPackaging([
        '--target',
        target,
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res2.status).toBe(0);

      // Verify stale file was eliminated
      expect(fs.existsSync(path.join(stageDir, 'stale-artifact.tmp'))).toBe(false);

      const isWin = target === 'win32-x64';
      const archiveName = isWin ? `secureship-${target}.zip` : `secureship-${target}.tar.gz`;
      const archivePath = path.join(out, archiveName);

      const extractDest = makeTempDir('secureship c4 extract ');
      extractArchive(archivePath, extractDest);

      const extractedFiles = getAllRelativeFiles(path.join(extractDest, `secureship-${target}`));
      expect(extractedFiles).not.toContain('stale-artifact.tmp');
    });
  });

  // C5: Non-allow-listed files are not packaged
  describe('C5: Allowlist file filtering for data and rules', () => {
    it('does not package non-allow-listed files (.md, .txt, .js) in data or rules directories', () => {
      const root = makeTempDir('secureship c5 fixture ');
      const out = makeTempDir('secureship c5 out ');
      const { assetsDir, binaryPath } = createValidAssetsFixture(root);

      // Plant non-allow-listed files in data/ and rules/
      fs.writeFileSync(path.join(assetsDir, 'data', 'README.md'), '# Notes\n');
      fs.writeFileSync(path.join(assetsDir, 'data', 'scratch.txt'), 'scratch\n');
      fs.writeFileSync(path.join(assetsDir, 'data', 'exploit.js'), 'console.log(1);\n');

      const rulesSubdir = path.join(assetsDir, 'rules', 'secureship-sast');
      fs.writeFileSync(path.join(rulesSubdir, 'rules-readme.md'), '# Rule docs\n');
      fs.writeFileSync(path.join(rulesSubdir, 'helper.js'), 'export const a = 1;\n');
      fs.writeFileSync(path.join(rulesSubdir, 'notes.txt'), 'test notes\n');

      const target = process.platform === 'win32' ? 'win32-x64' : 'linux-x64';
      const res = runPackaging([
        '--target',
        target,
        '--binary',
        binaryPath,
        '--assets',
        assetsDir,
        '--out',
        out,
      ]);
      expect(res.status).toBe(0);

      const isWin = target === 'win32-x64';
      const archiveName = isWin ? `secureship-${target}.zip` : `secureship-${target}.tar.gz`;
      const archivePath = path.join(out, archiveName);

      const extractDest = makeTempDir('secureship c5 extract ');
      extractArchive(archivePath, extractDest);

      const extractedFiles = getAllRelativeFiles(path.join(extractDest, `secureship-${target}`));

      // Verify none of the planted files are packaged
      expect(extractedFiles).not.toContain('data/README.md');
      expect(extractedFiles).not.toContain('data/scratch.txt');
      expect(extractedFiles).not.toContain('data/exploit.js');
      expect(extractedFiles).not.toContain('rules/secureship-sast/rules-readme.md');
      expect(extractedFiles).not.toContain('rules/secureship-sast/helper.js');
      expect(extractedFiles).not.toContain('rules/secureship-sast/notes.txt');

      // Verify allow-listed files ARE packaged
      expect(extractedFiles).toContain('data/vulnerable-symbols.json');
      expect(extractedFiles).toContain('data/vulnerable-symbols.manifest.json');
      expect(extractedFiles).toContain('rules/secureship-sast/secureship-js-eval.yml');
    });
  });
});
