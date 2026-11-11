import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawn, spawnSync, execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..');

const isGatedOff = process.env.RUN_STANDALONE_E2E === '0';
const isWin = process.platform === 'win32';
const target = isWin ? 'win32-x64' : 'linux-x64';
const binName = isWin ? 'secureship.exe' : 'secureship';
const archiveName = isWin ? `secureship-${target}.zip` : `secureship-${target}.tar.gz`;

describe(
  'LAYER E & F: Standalone Executable E2E & Negative Controls (DEV-5)',
  { timeout: 180_000 },
  () => {
    if (isGatedOff) {
      console.log('Standalone E2E tests skipped: RUN_STANDALONE_E2E is explicitly disabled ("0").');
      return;
    }

    let tempBase: string;
    let extractedStageDir: string;
    let standaloneBinPath: string;
    let emptyCwd: string;

    function runCmd(
      bin: string,
      args: string[],
      opts: { cwd?: string; env?: NodeJS.ProcessEnv; timeout?: number } = {}
    ): Promise<{
      status: number | null;
      signal: NodeJS.Signals | null;
      stdout: string;
      stderr: string;
    }> {
      return new Promise((resolve, reject) => {
        const child = spawn(bin, args, {
          cwd: opts.cwd ?? emptyCwd,
          env: opts.env ?? process.env,
          timeout: opts.timeout ?? 60_000,
          windowsHide: true,
        });
        let stdout = '';
        let stderr = '';
        child.stdout?.on('data', (d) => {
          stdout += d.toString();
        });
        child.stderr?.on('data', (d) => {
          stderr += d.toString();
        });
        child.on('error', reject);
        child.on('close', (code, sig) => {
          resolve({ status: code, signal: sig, stdout, stderr });
        });
      });
    }

    function runStandalone(
      args: string[],
      opts: { cwd?: string; env?: NodeJS.ProcessEnv; timeout?: number } = {}
    ) {
      return runCmd(standaloneBinPath, args, opts);
    }

    function extractArchive(archivePath: string, extractDest: string): void {
      if (archivePath.endsWith('.zip')) {
        if (isWin) {
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
        execSync(`tar -xzf "${archivePath}" -C "${extractDest}"`, {
          stdio: 'pipe',
          timeout: 60_000,
        });
      }
    }

    beforeAll(() => {
      tempBase = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship e2e space '));
      emptyCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-empty-cwd-'));

      // 1. Ensure binary is compiled and packaged
      const releaseDist = path.resolve(repoRoot, 'release-dist');
      const existingArchive = path.join(releaseDist, archiveName);

      if (!fs.existsSync(existingArchive)) {
        console.log('Compiling binary with Bun and packaging for standalone E2E tests...');
        fs.mkdirSync(releaseDist, { recursive: true });
        const rawBinPath = path.join(
          releaseDist,
          isWin ? 'secureship-win32-x64.exe' : 'secureship-linux-x64'
        );

        execSync(
          `bun build packages/cli/dist/index.js --compile --target bun-${target} --outfile ${rawBinPath}`,
          { cwd: repoRoot, stdio: 'pipe', timeout: 120_000 }
        );

        execSync(
          `node scripts/release/package-standalone.mjs --target ${target} --binary ${rawBinPath} --assets packages/cli/dist --out release-dist`,
          { cwd: repoRoot, stdio: 'pipe', timeout: 120_000 }
        );
      }

      // 2. Extract into directory with spaces
      extractArchive(existingArchive, tempBase);
      extractedStageDir = path.join(tempBase, `secureship-${target}`);
      standaloneBinPath = path.join(extractedStageDir, binName);

      if (!isWin) {
        fs.chmodSync(standaloneBinPath, 0o755);
      }

      expect(fs.existsSync(standaloneBinPath)).toBe(true);
    });

    afterAll(() => {
      try {
        if (tempBase && fs.existsSync(tempBase)) {
          fs.rmSync(tempBase, { recursive: true, force: true });
        }
        if (emptyCwd && fs.existsSync(emptyCwd)) {
          fs.rmSync(emptyCwd, { recursive: true, force: true });
        }
      } catch {
        // ignore
      }
    });

    // --- LAYER E: Real compiled binary verification ---
    describe('LAYER E: Real compiled standalone binary', () => {
      it('E1: --version exits 0 and prints valid version', async () => {
        const res = await runStandalone(['--version']);
        expect(res.status).toBe(0);
        expect(res.stdout.trim()).toMatch(/\d+\.\d+\.\d+/);
      });

      it('E2: WASM verification passes for all 9 grammars from <execDir>/wasm', async () => {
        const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-e2-fixture-'));
        try {
          fs.writeFileSync(path.join(fixtureDir, 'index.js'), 'const x = 1;\nconsole.log(x);\n');
          const res = await runStandalone(['scan', fixtureDir, '--no-color']);
          const combined = (res.stdout || '') + '\n' + (res.stderr || '');

          expect(combined).not.toContain('WASM directory not found');
          expect(combined).not.toContain('Integrity check failed');
          expect(res.status).toBe(0);
        } finally {
          fs.rmSync(fixtureDir, { recursive: true, force: true });
        }
      });

      it('E3: scan of lodash fixture completes with clean output and reachability analysis', async () => {
        const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-e3-lodash-'));
        try {
          fs.writeFileSync(
            path.join(fixtureDir, 'package.json'),
            JSON.stringify(
              {
                name: 'lodash-fixture',
                version: '1.0.0',
                dependencies: { lodash: '4.17.20' },
              },
              null,
              2
            )
          );
          fs.writeFileSync(
            path.join(fixtureDir, 'package-lock.json'),
            JSON.stringify(
              {
                name: 'lodash-fixture',
                version: '1.0.0',
                lockfileVersion: 2,
                requires: true,
                packages: {
                  '': {
                    name: 'lodash-fixture',
                    version: '1.0.0',
                    dependencies: { lodash: '4.17.20' },
                  },
                  'node_modules/lodash': {
                    version: '4.17.20',
                    resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
                    integrity:
                      'sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshqCiNlJYVuCLJwpVQx5uPISgVCWBRI6EXPmLEQqydAT6l8tYZw==',
                  },
                },
                dependencies: {
                  lodash: {
                    version: '4.17.20',
                    resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
                    integrity:
                      'sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshqCiNlJYVuCLJwpVQx5uPISgVCWBRI6EXPmLEQqydAT6l8tYZw==',
                  },
                },
              },
              null,
              2
            )
          );
          fs.writeFileSync(
            path.join(fixtureDir, 'index.js'),
            "import _ from 'lodash';\nconst compiled = _.template('hello <%= user %>!');\nconsole.log(compiled({ user: 'world' }));\n"
          );

          const res = await runStandalone(['scan', fixtureDir, '--no-color']);
          const combined = (res.stdout || '') + '\n' + (res.stderr || '');

          // Forbidden strings
          const forbidden = [
            'WASM directory not found',
            'ENOENT',
            'Symbol dataset file not found',
            'Integrity check failed',
            'NOT from the bundled',
            'Curated vulnerable symbol dataset is unavailable',
            'dataset-unavailable',
          ];
          for (const f of forbidden) {
            expect(combined).not.toContain(f);
          }

          expect(combined).toContain('CVE-2021-23337');
          expect(combined).toContain('[IMPORTED]');
          expect(res.signal).toBeNull();
        } finally {
          fs.rmSync(fixtureDir, { recursive: true, force: true });
        }
      });

      it('E4: SAST scanner execution or graceful TOOL_MISSING detection', async () => {
        const opengrepAvailable =
          spawnSync(isWin ? 'where' : 'which', ['opengrep'], { encoding: 'utf-8' }).status === 0 ||
          spawnSync(isWin ? 'where' : 'which', ['semgrep'], { encoding: 'utf-8' }).status === 0;

        const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-e4-sast-'));
        try {
          fs.writeFileSync(
            path.join(fixtureDir, 'app.js'),
            "const { exec } = require('child_process');\nconst cmd = 'ls ' + req.query.cmd;\nexec(cmd);\n"
          );

          const res = await runStandalone(['scan', fixtureDir, '--no-color']);
          const combined = (res.stdout || '') + '\n' + (res.stderr || '');

          if (opengrepAvailable) {
            expect(combined).not.toContain('missing rulepack');
            expect(combined).toMatch(/SecureShip SAST\s+\d+\.\d+\.\d+\s+SUCCESS/);
            expect(combined).toContain('SS-SAST-js-child-process-exec');
          } else {
            console.log('SAST execution skipped: binary unavailable');
            expect(combined).toContain('TOOL_MISSING');
            expect(combined).not.toContain('Crash: missing-rule-path');
          }
        } finally {
          fs.rmSync(fixtureDir, { recursive: true, force: true });
        }
      });

      it('E5: POSIX symlink resolution', async () => {
        if (isWin) {
          // Windows symlink permissions may vary; test graceful fallback or skip
          return;
        }

        const symlinkBase = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-e5-symlink-'));
        try {
          const symlinkPath = path.join(symlinkBase, 'secureship');
          fs.symlinkSync(standaloneBinPath, symlinkPath);

          const res = await runCmd(symlinkPath, ['--version']);

          expect(res.status).toBe(0);
          expect(res.stdout.trim()).toMatch(/\d+\.\d+\.\d+/);
        } finally {
          fs.rmSync(symlinkBase, { recursive: true, force: true });
        }
      });
    });

    // --- LAYER F: Negative Controls ---
    describe('LAYER F: Negative Controls', () => {
      it('F1: Copy ONLY binary to empty directory -> non-zero exit and standalone hint text', async () => {
        const loneDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-f1-lone-'));
        const testProject = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-f1-proj-'));
        try {
          const loneBin = path.join(loneDir, binName);
          fs.copyFileSync(standaloneBinPath, loneBin);
          if (!isWin) fs.chmodSync(loneBin, 0o755);

          fs.writeFileSync(path.join(testProject, 'index.js'), 'const a = 1;\n');

          // Phase 1: Pure lone binary without any accompanying release assets fails non-zero
          const resPure = await runCmd(loneBin, ['scan', testProject, '--no-color']);
          expect(resPure.status).not.toBe(0);

          // Phase 2: Copy tools.lock.json into lone directory to isolate Tree-sitter WASM search behavior
          const srcLock = path.join(extractedStageDir, 'tools.lock.json');
          if (fs.existsSync(srcLock)) {
            fs.copyFileSync(srcLock, path.join(loneDir, 'tools.lock.json'));
          }

          const resWasm = await runCmd(loneBin, ['graph', testProject]);
          expect(resWasm.status).not.toBe(0);
          const combinedWasm = (resWasm.stdout || '') + '\n' + (resWasm.stderr || '');
          expect(combinedWasm).toContain(
            'Standalone binary detected: keep the binary inside the extracted release folder'
          );
        } finally {
          fs.rmSync(loneDir, { recursive: true, force: true });
          fs.rmSync(testProject, { recursive: true, force: true });
        }
      });

      it('F2: Delete <extract>/wasm -> fails with WASM not found error and standalone hint, restores afterwards', async () => {
        const wasmDir = path.join(extractedStageDir, 'wasm');
        const wasmBackup = path.join(extractedStageDir, 'wasm_backup_f2');
        const testProject = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-f2-proj-'));

        try {
          fs.writeFileSync(path.join(testProject, 'index.js'), 'const a = 1;\n');
          fs.renameSync(wasmDir, wasmBackup);

          const res = await runStandalone(['graph', testProject]);
          expect(res.status).not.toBe(0);

          const combined = (res.stdout || '') + '\n' + (res.stderr || '');
          expect(combined).toContain('WASM directory not found');
          expect(combined).toContain(
            'Standalone binary detected: keep the binary inside the extracted release folder'
          );
        } finally {
          if (fs.existsSync(wasmBackup)) {
            fs.renameSync(wasmBackup, wasmDir);
          }
          fs.rmSync(testProject, { recursive: true, force: true });
        }
      });

      it('F3: Missing data/ and missing rules/ handled gracefully without crash', async () => {
        const dataDir = path.join(extractedStageDir, 'data');
        const dataBackup = path.join(extractedStageDir, 'data_backup_f3');
        const rulesDir = path.join(extractedStageDir, 'rules');
        const rulesBackup = path.join(extractedStageDir, 'rules_backup_f3');
        const testProject = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-f3-proj-'));

        try {
          fs.writeFileSync(path.join(testProject, 'index.js'), 'const a = 1;\n');

          // Test missing data/: doctor warns about unavailable/degraded dataset
          fs.renameSync(dataDir, dataBackup);
          const resDoctor = await runStandalone(['doctor']);
          const combinedDoctor = (resDoctor.stdout || '') + '\n' + (resDoctor.stderr || '');
          expect(
            combinedDoctor.includes('Curated vulnerable symbol dataset is unavailable') ||
              combinedDoctor.includes('Integrity check failed') ||
              combinedDoctor.includes('0 verified entries') ||
              combinedDoctor.includes('fallback directory')
          ).toBe(true);

          const resData = await runStandalone(['scan', testProject, '--no-color']);
          expect(resData.status).toBe(0);
          expect(resData.signal).toBeNull();

          // Restore data
          fs.renameSync(dataBackup, dataDir);

          // Test missing rules/
          fs.renameSync(rulesDir, rulesBackup);
          const resRules = await runStandalone(['scan', testProject, '--no-color']);
          expect(resRules.signal).toBeNull(); // No crash/segfault
          expect(resRules.status).toBe(0);
        } finally {
          if (fs.existsSync(dataBackup)) {
            fs.renameSync(dataBackup, dataDir);
          }
          if (fs.existsSync(rulesBackup)) {
            fs.renameSync(rulesBackup, rulesDir);
          }
          fs.rmSync(testProject, { recursive: true, force: true });
        }
      });

      it('F4: SECURESHIP_WASM_DIR pointing at valid wasm makes F1 lone binary pass', async () => {
        const loneDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-f4-lone-'));
        const testProject = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-f4-proj-'));

        try {
          const loneBin = path.join(loneDir, binName);
          fs.copyFileSync(standaloneBinPath, loneBin);
          if (!isWin) fs.chmodSync(loneBin, 0o755);

          const srcLock = path.join(extractedStageDir, 'tools.lock.json');
          if (fs.existsSync(srcLock)) {
            fs.copyFileSync(srcLock, path.join(loneDir, 'tools.lock.json'));
          }

          fs.writeFileSync(path.join(testProject, 'index.js'), 'const a = 1;\n');

          const validWasmDir = path.join(extractedStageDir, 'wasm');
          const res = await runCmd(loneBin, ['graph', testProject], {
            cwd: emptyCwd,
            env: {
              ...process.env,
              SECURESHIP_WASM_DIR: validWasmDir,
            },
          });

          const combined = (res.stdout || '') + '\n' + (res.stderr || '');
          expect(combined).not.toContain('WASM directory not found');
          expect(res.status).toBe(0);
          expect(res.stdout).toContain('SecureShip Import Graph');
        } finally {
          fs.rmSync(loneDir, { recursive: true, force: true });
          fs.rmSync(testProject, { recursive: true, force: true });
        }
      });

      it('F5: cwd-shadow attack defense: decoy assets in target project never override genuine release assets', async () => {
        const shadowProject = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-f5-shadow-'));

        try {
          // Plant decoy wasm with invalid tree-sitter.wasm
          const decoyWasm = path.join(shadowProject, 'packages/reachability/wasm');
          fs.mkdirSync(decoyWasm, { recursive: true });
          fs.writeFileSync(path.join(decoyWasm, 'tree-sitter.wasm'), Buffer.alloc(128, 0x00));

          // Plant decoy data with canary CVE
          const decoyData = path.join(shadowProject, 'packages/reachability/data');
          fs.mkdirSync(decoyData, { recursive: true });
          const canaryObj = {
            version: '1.0',
            datasetId: 'canary-dataset',
            entries: [
              {
                id: 'CVE-CANARY-SHADOW',
                aliases: [],
                ecosystem: 'npm',
                package: 'canary',
                entryPoints: [{ module: '.', export: 'canary', kind: 'FUNCTION' }],
                triggeredOn: 'CALL',
                entryPointsComplete: true,
                sourceUrls: ['https://example.com'],
                fixCommitUrls: ['https://example.com/fix'],
                verifiedAt: '2026-10-28',
                verifiedBy: 'tester',
                notes: 'canary',
              },
            ],
          };
          const canaryBuf = Buffer.from(JSON.stringify(canaryObj, null, 2));
          const canaryHash = crypto.createHash('sha256').update(canaryBuf).digest('hex');
          fs.writeFileSync(path.join(decoyData, 'vulnerable-symbols.json'), canaryBuf);
          fs.writeFileSync(
            path.join(decoyData, 'vulnerable-symbols.manifest.json'),
            JSON.stringify({ schemaVersion: '1.0', sha256: canaryHash, totalSymbols: 1 })
          );

          // Plant decoy rule
          const decoyRules = path.join(shadowProject, 'rules/secureship-sast');
          fs.mkdirSync(decoyRules, { recursive: true });
          fs.writeFileSync(
            path.join(decoyRules, 'canary-shadow-rule.yml'),
            'rules:\n  - id: canary-shadow-rule\n    message: canary\n    severity: ERROR\n    languages: [javascript]\n    pattern: canary(...)\n'
          );

          fs.writeFileSync(path.join(shadowProject, 'index.js'), 'const a = 1;\n');

          // Run standalone from the shadowProject as cwd
          const res = await runStandalone(['scan', shadowProject, '--no-color'], {
            cwd: shadowProject,
          });
          const combined = (res.stdout || '') + '\n' + (res.stderr || '');

          // Canary rule and dataset must NEVER be used
          expect(combined).not.toContain('CVE-CANARY-SHADOW');
          expect(combined).not.toContain('canary-shadow-rule');
          // Genuine wasm adjacent to binary must win (no crash or tamper error)
          expect(combined).not.toContain('Security violation');
          expect(res.status).toBe(0);
        } finally {
          fs.rmSync(shadowProject, { recursive: true, force: true });
        }
      });
    });
  }
);
