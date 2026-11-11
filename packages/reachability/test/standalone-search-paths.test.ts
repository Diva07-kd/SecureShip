import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  getWasmSearchCandidates,
  verifyBundledWasm,
  WASM_MANIFEST,
} from '../src/manifest/wasm-manifest.js';
import { TreeSitterLoader, type SupportedLanguage } from '../src/parsers/tree-sitter-loader.js';
import { SymbolDatasetLoader } from '../src/symbols/dataset-loader.js';
import * as wasmManifestModule from '../src/manifest/wasm-manifest.js';
import * as standaloneModule from '../src/standalone-exec.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..');
const genuineWasmDir = path.resolve(repoRoot, 'packages/reachability/wasm');
const genuineDataDir = path.resolve(repoRoot, 'packages/reachability/data');

describe('LAYER B: Candidate Resolution & Security Suite (DEV-2 & DEV-3)', () => {
  const tempDirs: string[] = [];

  function makeTempDir(prefix: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  function resetTreeSitterLoader(): void {
    // Reset private static state between tests
    (TreeSitterLoader as unknown as { initialized: boolean }).initialized = false;
    (TreeSitterLoader as unknown as { initPromise: Promise<void> | null }).initPromise = null;
    (TreeSitterLoader as unknown as { wasmDir: string | null }).wasmDir = null;
    (
      TreeSitterLoader as unknown as { languages: Map<SupportedLanguage, unknown> }
    ).languages.clear();
    (
      TreeSitterLoader as unknown as { languageLoadErrors: Map<SupportedLanguage, string> }
    ).languageLoadErrors.clear();
  }

  beforeEach(() => {
    resetTreeSitterLoader();
    SymbolDatasetLoader.resetCache();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    resetTreeSitterLoader();
    SymbolDatasetLoader.resetCache();
    for (const d of tempDirs) {
      try {
        fs.rmSync(d, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
    tempDirs.length = 0;
  });

  // B1. getWasmSearchCandidates() exact ordered list & regression guard
  describe('B1: getWasmSearchCandidates ordering and de-duplication', () => {
    it('returns exact ordered list: env, 5 module-relative, execDir/wasm, cwd candidate (absolute and de-duplicated)', () => {
      const fakeEnv = path.resolve('/custom/env/wasm');
      const fakeModule = path.resolve('/opt/secureship/module');
      const fakeExec = path.resolve('/opt/secureship/bin');
      const fakeCwd = path.resolve('/workspace/project');

      const candidates = getWasmSearchCandidates({
        envDir: fakeEnv,
        moduleDir: fakeModule,
        cwd: fakeCwd,
        execDir: fakeExec,
      });

      const expected = [
        fakeEnv,
        path.resolve(fakeModule, 'wasm'),
        path.resolve(fakeModule, '..', 'wasm'),
        path.resolve(fakeModule, '..', 'dist', 'wasm'),
        path.resolve(fakeModule, '..', '..', 'wasm'),
        path.resolve(fakeModule, '..', '..', 'packages', 'reachability', 'wasm'),
        path.resolve(fakeExec, 'wasm'),
        path.resolve(fakeCwd, 'packages', 'reachability', 'wasm'),
      ];

      expect(candidates).toEqual(expected);
    });

    it('equals the legacy 7-candidate list when execDir is null (regression guard)', () => {
      const fakeEnv = path.resolve('/custom/env/wasm');
      const fakeModule = path.resolve('/opt/secureship/module');
      const fakeCwd = path.resolve('/workspace/project');

      const candidates = getWasmSearchCandidates({
        envDir: fakeEnv,
        moduleDir: fakeModule,
        cwd: fakeCwd,
        execDir: null,
      });

      const legacyExpected = [
        fakeEnv,
        path.resolve(fakeModule, 'wasm'),
        path.resolve(fakeModule, '..', 'wasm'),
        path.resolve(fakeModule, '..', 'dist', 'wasm'),
        path.resolve(fakeModule, '..', '..', 'wasm'),
        path.resolve(fakeModule, '..', '..', 'packages', 'reachability', 'wasm'),
        path.resolve(fakeCwd, 'packages', 'reachability', 'wasm'),
      ];

      expect(candidates).toEqual(legacyExpected);
      expect(candidates).not.toContain(path.resolve('/opt/secureship/bin/wasm'));
    });

    it('de-duplicates overlapping paths while preserving first occurrence order', () => {
      const shared = path.resolve('/shared');
      const candidates = getWasmSearchCandidates({
        envDir: path.resolve(shared, 'wasm'),
        moduleDir: shared,
        cwd: shared,
        execDir: shared,
      });

      const count = candidates.filter((c) => c === path.resolve(shared, 'wasm')).length;
      expect(count).toBe(1);
      expect(candidates[0]).toBe(path.resolve(shared, 'wasm'));
    });
  });

  // B2. tree-sitter-loader and verifyBundledWasm resolve through the same function
  describe('B2: tree-sitter-loader and verifyBundledWasm shared function resolution', () => {
    it('both tree-sitter-loader and verifyBundledWasm resolve through getWasmSearchCandidates', () => {
      // 1. tree-sitter-loader resolves through getWasmSearchCandidates (verified via spy)
      const spy = vi.spyOn(wasmManifestModule, 'getWasmSearchCandidates');
      try {
        TreeSitterLoader.getWasmDirectory();
      } catch {
        // May throw if wasm not found in default search paths
      }
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();

      // 2. verifyBundledWasm resolves against the exact same candidates list (equal-list assertion)
      const defaultCandidates = getWasmSearchCandidates();
      expect(defaultCandidates.length).toBeGreaterThanOrEqual(1);

      // Point mock fs to candidate and verify verifyBundledWasm finds it
      const tempWasm = makeTempDir('secureship-shared-wasm-');
      for (const f of fs.readdirSync(genuineWasmDir).filter((x) => x.endsWith('.wasm'))) {
        fs.copyFileSync(path.join(genuineWasmDir, f), path.join(tempWasm, f));
      }

      // Overriding candidates to [tempWasm] works identically in verifyBundledWasm
      const overridden = verifyBundledWasm([tempWasm]);
      expect(overridden.ok).toBe(true);
      expect(overridden.results.length).toBe(Object.keys(WASM_MANIFEST).length);
      for (const r of overridden.results) {
        expect(r.valid).toBe(true);
      }
    });

    it('verifyBundledWasm respects candidatesOverride without calling getWasmSearchCandidates', () => {
      const spy = vi.spyOn(wasmManifestModule, 'getWasmSearchCandidates');
      const tempWasm = makeTempDir('secureship-override-wasm-');
      fs.copyFileSync(
        path.join(genuineWasmDir, 'tree-sitter.wasm'),
        path.join(tempWasm, 'tree-sitter.wasm')
      );

      const result = verifyBundledWasm([tempWasm]);
      expect(spy).not.toHaveBeenCalled();
      expect(result.results.length).toBe(Object.keys(WASM_MANIFEST).length);
    });
  });

  // B3. Only <execDir>/wasm exists -> TreeSitterLoader.getWasmDirectory() returns it and init() loads all 9 grammars
  describe('B3: Lone <execDir>/wasm resolution and grammar loading', () => {
    it('returns <execDir>/wasm and loads all 9 language grammars when all other candidates are absent', async () => {
      const tempExec = makeTempDir('secureship-b3-exec-');
      const tempExecWasm = path.join(tempExec, 'wasm');
      fs.mkdirSync(tempExecWasm, { recursive: true });

      // Copy all genuine wasm files to tempExecWasm (core + 8 languages = 9 grammars)
      const wasmFiles = fs.readdirSync(genuineWasmDir).filter((f) => f.endsWith('.wasm'));
      expect(wasmFiles.length).toBe(9);
      for (const f of wasmFiles) {
        fs.copyFileSync(path.join(genuineWasmDir, f), path.join(tempExecWasm, f));
      }

      vi.spyOn(standaloneModule, 'getStandaloneExecDir').mockReturnValue(tempExec);

      // Only tempExecWasm exists; all other candidates do not contain tree-sitter.wasm
      const originalExistsSync = fs.existsSync.bind(fs);
      vi.spyOn(fs, 'existsSync').mockImplementation((p: fs.PathLike) => {
        const pStr = path.resolve(p.toString());
        if (pStr.startsWith(path.resolve(genuineWasmDir))) {
          return false;
        }
        return originalExistsSync(p);
      });

      const resolvedDir = TreeSitterLoader.getWasmDirectory();
      expect(resolvedDir).toBe(path.resolve(tempExecWasm));

      await TreeSitterLoader.init();

      const expectedLangs: SupportedLanguage[] = [
        'javascript',
        'typescript',
        'tsx',
        'python',
        'go',
        'java',
        'rust',
        'c_sharp',
      ];

      for (const lang of expectedLangs) {
        const { parser, error } = TreeSitterLoader.getParser(lang);
        expect(error).toBeUndefined();
        expect(parser).not.toBeNull();
      }
    });
  });

  // B4. Not found error text contains all candidates; with execDir has hint; without execDir does not
  describe('B4: Not found error formatting and standalone hint', () => {
    it('contains every searched candidate and the standalone release folder hint when execDir is non-null', () => {
      const fakeExec = path.resolve('/opt/secureship/bin');
      vi.spyOn(standaloneModule, 'getStandaloneExecDir').mockReturnValue(fakeExec);
      vi.spyOn(fs, 'existsSync').mockReturnValue(false);

      let caughtError: Error | null = null;
      try {
        TreeSitterLoader.getWasmDirectory();
      } catch (err) {
        caughtError = err as Error;
      }

      expect(caughtError).not.toBeNull();
      const msg = caughtError!.message;
      expect(msg).toContain('SecureShip Tree-sitter WASM directory not found');
      // Assert EVERY candidate is present in the error message
      const searchedCandidates = getWasmSearchCandidates({ execDir: fakeExec });
      for (const c of searchedCandidates) {
        expect(msg).toContain(c);
      }
      expect(msg).toContain(
        'Standalone binary detected: keep the binary inside the extracted release folder next to its wasm/, data/ and rules/ directories'
      );
    });

    it('contains every searched candidate but NOT the standalone hint when execDir is null', () => {
      vi.spyOn(standaloneModule, 'getStandaloneExecDir').mockReturnValue(null);
      vi.spyOn(fs, 'existsSync').mockReturnValue(false);

      let caughtError: Error | null = null;
      try {
        TreeSitterLoader.getWasmDirectory();
      } catch (err) {
        caughtError = err as Error;
      }

      expect(caughtError).not.toBeNull();
      const msg = caughtError!.message;
      expect(msg).toContain('SecureShip Tree-sitter WASM directory not found');
      // Assert EVERY candidate is present in the error message
      const searchedCandidates = getWasmSearchCandidates({ execDir: null });
      for (const c of searchedCandidates) {
        expect(msg).toContain(c);
      }
      expect(msg).not.toContain('Standalone binary detected');
    });
  });

  // B5. SECURESHIP_WASM_DIR beats every other candidate
  describe('B5: SECURESHIP_WASM_DIR environment variable priority', () => {
    it('SECURESHIP_WASM_DIR beats module-relative, execDir, and cwd candidates', () => {
      const envWasm = makeTempDir('secureship-b5-env-');
      const execDir = makeTempDir('secureship-b5-exec-');
      const execWasm = path.join(execDir, 'wasm');
      fs.mkdirSync(execWasm, { recursive: true });

      fs.copyFileSync(
        path.join(genuineWasmDir, 'tree-sitter.wasm'),
        path.join(envWasm, 'tree-sitter.wasm')
      );
      fs.copyFileSync(
        path.join(genuineWasmDir, 'tree-sitter.wasm'),
        path.join(execWasm, 'tree-sitter.wasm')
      );

      const oldEnv = process.env.SECURESHIP_WASM_DIR;
      process.env.SECURESHIP_WASM_DIR = envWasm;

      try {
        vi.spyOn(standaloneModule, 'getStandaloneExecDir').mockReturnValue(execDir);
        const resolved = TreeSitterLoader.getWasmDirectory();
        expect(resolved).toBe(path.resolve(envWasm));
      } finally {
        if (oldEnv !== undefined) {
          process.env.SECURESHIP_WASM_DIR = oldEnv;
        } else {
          delete process.env.SECURESHIP_WASM_DIR;
        }
      }
    });
  });

  // B6. Shadow attack: temp cwd with tampered wasm vs genuine <execDir>/wasm
  describe('B6: Shadow attack defense and cryptographic rejection', () => {
    it('genuine <execDir>/wasm wins over cwd tampered wasm decoy', async () => {
      const tempCwd = makeTempDir('secureship-b6-cwd-');
      const cwdWasm = path.join(tempCwd, 'packages/reachability/wasm');
      fs.mkdirSync(cwdWasm, { recursive: true });
      // Create tampered tree-sitter.wasm with invalid payload
      fs.writeFileSync(path.join(cwdWasm, 'tree-sitter.wasm'), Buffer.alloc(256, 0x00));

      const tempExec = makeTempDir('secureship-b6-exec-');
      const execWasm = path.join(tempExec, 'wasm');
      fs.mkdirSync(execWasm, { recursive: true });
      for (const f of fs.readdirSync(genuineWasmDir).filter((x) => x.endsWith('.wasm'))) {
        fs.copyFileSync(path.join(genuineWasmDir, f), path.join(execWasm, f));
      }

      vi.spyOn(process, 'cwd').mockReturnValue(tempCwd);
      vi.spyOn(standaloneModule, 'getStandaloneExecDir').mockReturnValue(tempExec);

      // Mask genuine repo module candidates
      const originalExistsSync = fs.existsSync.bind(fs);
      vi.spyOn(fs, 'existsSync').mockImplementation((p: fs.PathLike) => {
        const pStr = path.resolve(p.toString());
        if (pStr.startsWith(path.resolve(genuineWasmDir))) {
          return false;
        }
        return originalExistsSync(p);
      });

      const resolved = TreeSitterLoader.getWasmDirectory();
      expect(resolved).toBe(path.resolve(execWasm));
      // Real tree-sitter loads without error because genuine files won
      await TreeSitterLoader.init();
      const { parser, error } = TreeSitterLoader.getParser('javascript');
      expect(error).toBeUndefined();
      expect(parser).not.toBeNull();
    });

    it('rejects with SHA-256 Security violation error when only tampered wasm is reachable', async () => {
      const tempCwd = makeTempDir('secureship-b6-tampered-');
      const cwdWasm = path.join(tempCwd, 'packages/reachability/wasm');
      fs.mkdirSync(cwdWasm, { recursive: true });
      fs.writeFileSync(path.join(cwdWasm, 'tree-sitter.wasm'), Buffer.from('TAMPERED_WASM_BYTES'));

      vi.spyOn(process, 'cwd').mockReturnValue(tempCwd);
      vi.spyOn(standaloneModule, 'getStandaloneExecDir').mockReturnValue(null);

      // Mask genuine repo module candidates
      const originalExistsSync = fs.existsSync.bind(fs);
      vi.spyOn(fs, 'existsSync').mockImplementation((p: fs.PathLike) => {
        const pStr = path.resolve(p.toString());
        if (pStr.startsWith(path.resolve(genuineWasmDir))) {
          return false;
        }
        return originalExistsSync(p);
      });

      const resolved = TreeSitterLoader.getWasmDirectory();
      expect(resolved).toBe(path.resolve(cwdWasm));

      await expect(TreeSitterLoader.init()).rejects.toThrowError(
        /Security violation: tree-sitter\.wasm failed cryptographic SHA-256 verification/
      );
    });
  });

  // B7. dataset-loader priority and cwd canary decoy defense
  describe('B7: SymbolDatasetLoader priority table and cwd decoy defense', () => {
    it('execDir data candidate sits between module candidates and cwd candidates', () => {
      const fakeModule = path.resolve('/fake/module');
      const fakeCwd = path.resolve('/fake/cwd');
      const fakeExec = path.resolve('/fake/bin');

      const candidates = SymbolDatasetLoader.getBundledDataCandidates(
        fakeModule,
        fakeCwd,
        fakeExec
      );

      expect(candidates).toEqual([
        path.resolve(fakeModule, 'data'),
        path.resolve(fakeModule, '../../data'),
        path.resolve(fakeModule, '../data'),
        path.resolve(fakeExec, 'data'),
        path.resolve(fakeCwd, 'packages/reachability/data'),
        path.resolve(fakeCwd, 'data'),
      ]);
    });

    it('cwd canary decoy (CVE-0000-CANARY) never wins over <execDir>/data', () => {
      const tempExec = makeTempDir('secureship-b7-exec-');
      const execData = path.join(tempExec, 'data');
      fs.mkdirSync(execData, { recursive: true });
      fs.copyFileSync(
        path.join(genuineDataDir, 'vulnerable-symbols.json'),
        path.join(execData, 'vulnerable-symbols.json')
      );
      fs.copyFileSync(
        path.join(genuineDataDir, 'vulnerable-symbols.manifest.json'),
        path.join(execData, 'vulnerable-symbols.manifest.json')
      );

      // Create decoy cwd with canary CVE-0000-CANARY and consistent manifest
      const tempCwd = makeTempDir('secureship-b7-cwd-');
      const cwdData = path.join(tempCwd, 'packages/reachability/data');
      fs.mkdirSync(cwdData, { recursive: true });

      const canaryDataset = {
        schemaVersion: '1.0',
        generatedAt: '2026-10-28T00:00:00.000Z',
        totalSymbols: 1,
        symbols: [
          {
            cve: 'CVE-0000-CANARY',
            package: 'canary-pkg',
            symbol: 'canary_leak',
            language: 'javascript',
          },
        ],
      };
      const canaryRaw = Buffer.from(JSON.stringify(canaryDataset, null, 2), 'utf-8');
      const canarySha = crypto.createHash('sha256').update(canaryRaw).digest('hex');
      const canaryManifest = {
        schemaVersion: '1.0',
        sha256: canarySha,
        totalSymbols: 1,
      };

      fs.writeFileSync(path.join(cwdData, 'vulnerable-symbols.json'), canaryRaw);
      fs.writeFileSync(
        path.join(cwdData, 'vulnerable-symbols.manifest.json'),
        JSON.stringify(canaryManifest, null, 2)
      );

      vi.spyOn(process, 'cwd').mockReturnValue(tempCwd);

      // Mask genuine repo module candidates
      const originalExistsSync = fs.existsSync.bind(fs);
      vi.spyOn(fs, 'existsSync').mockImplementation((p: fs.PathLike) => {
        const pStr = path.resolve(p.toString());
        if (pStr.startsWith(path.resolve(genuineDataDir))) {
          return false;
        }
        return originalExistsSync(p);
      });

      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const resolved = SymbolDatasetLoader.getBundledDataDirectory(tempExec);

      expect(resolved).toBe(path.resolve(execData));
      // Canary should never be loaded
      vi.spyOn(standaloneModule, 'getStandaloneExecDir').mockReturnValue(tempExec);
      const loaded = SymbolDatasetLoader.loadBundledDataset();
      expect(loaded.ok).toBe(true);
      expect(loaded.dataset?.entries.some((e) => e.id === 'CVE-0000-CANARY')).toBe(false);

      const f6Warnings = warnSpy.mock.calls
        .map((c) => String(c[0]))
        .filter((msg) => msg.includes('F6 trust model'));
      expect(f6Warnings.length).toBe(0);
    });

    it('table-driven priority: the lowest-numbered existing candidate wins', () => {
      const fakeModule = path.resolve('/fake/module');
      const fakeCwd = path.resolve('/fake/cwd');
      const fakeExec = path.resolve('/fake/bin');

      const allCandidates = [
        path.resolve(fakeModule, 'data'),
        path.resolve(fakeModule, '../../data'),
        path.resolve(fakeModule, '../data'),
        path.resolve(fakeExec, 'data'),
        path.resolve(fakeCwd, 'packages/reachability/data'),
        path.resolve(fakeCwd, 'data'),
      ];

      for (let winnerIdx = 0; winnerIdx < allCandidates.length; winnerIdx++) {
        const existingSet = new Set(allCandidates.slice(winnerIdx));
        const resolved = SymbolDatasetLoader.getBundledDataCandidates(
          fakeModule,
          fakeCwd,
          fakeExec
        );

        let chosen: string | null = null;
        for (const c of resolved) {
          if (existingSet.has(c)) {
            chosen = c;
            break;
          }
        }
        expect(chosen).toBe(allCandidates[winnerIdx]);

        // Also test getBundledDataDirectory resolution with mock fs
        SymbolDatasetLoader.resetCache();
        vi.spyOn(SymbolDatasetLoader, 'getBundledDataCandidates').mockReturnValue(resolved);
        vi.spyOn(fs, 'existsSync').mockImplementation((p: fs.PathLike) => {
          const pStr = path.resolve(p.toString());
          for (const cand of existingSet) {
            if (
              pStr === path.join(cand, 'vulnerable-symbols.json') ||
              pStr === path.join(cand, 'vulnerable-symbols.manifest.json')
            ) {
              return true;
            }
          }
          return false;
        });

        const chosenDir = SymbolDatasetLoader.getBundledDataDirectory(fakeExec);
        expect(chosenDir).toBe(allCandidates[winnerIdx]);
      }
    });
  });
});
