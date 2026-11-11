import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { SymbolDatasetLoader } from '../../src/symbols/dataset-loader.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const reachabilityDataDir = path.resolve(__dirname, '../../data');
const realModuleDir = path.resolve(__dirname, '../../src/symbols');

describe('Layer B - SymbolDatasetLoader Paths & F6 Trust Model Suite (DEV-3 / F-PKG-001)', () => {
  const tempDirs: string[] = [];

  function makeTempDir(prefix: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  beforeEach(() => {
    SymbolDatasetLoader.resetCache();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    SymbolDatasetLoader.resetCache();
    for (const d of tempDirs) {
      try {
        fs.rmSync(d, { recursive: true, force: true });
      } catch {
        // cleanup ignore
      }
    }
    tempDirs.length = 0;
  });

  it('B1: getBundledDataCandidates(moduleDir, cwd) returns exact 5-entry ordered list with de-duplication', () => {
    const fakeModuleDir = path.resolve('/fake/module/dir');
    const fakeCwd = path.resolve('/fake/cwd/dir');

    const expectedCandidates = [
      path.resolve(fakeModuleDir, 'data'),
      path.resolve(fakeModuleDir, '../../data'),
      path.resolve(fakeModuleDir, '../data'),
      path.resolve(fakeCwd, 'packages/reachability/data'),
      path.resolve(fakeCwd, 'data'),
    ];

    const actualCandidates = SymbolDatasetLoader.getBundledDataCandidates(fakeModuleDir, fakeCwd);

    expect(actualCandidates).toEqual(expectedCandidates);
    expect(actualCandidates.length).toEqual(5);

    // Test de-duplication: when fakeCwd/data coincides with fakeModuleDir/data
    const overlappingCwd = fakeModuleDir;
    const deduplicatedCandidates = SymbolDatasetLoader.getBundledDataCandidates(
      fakeModuleDir,
      overlappingCwd
    );

    const expectedDeduplicated = [
      path.resolve(fakeModuleDir, 'data'),
      path.resolve(fakeModuleDir, '../../data'),
      path.resolve(fakeModuleDir, '../data'),
      path.resolve(fakeModuleDir, 'packages/reachability/data'),
    ];

    expect(deduplicatedCandidates).toEqual(expectedDeduplicated);
    expect(deduplicatedCandidates.length).toEqual(4);
  });

  it('B2: real repository layout returns valid directory, loadBundledDataset ok:true, exact 18 entries, and valid sha256', () => {
    const bundledDir = SymbolDatasetLoader.getBundledDataDirectory();

    const dataFilePath = path.join(bundledDir, 'vulnerable-symbols.json');
    const manifestFilePath = path.join(bundledDir, 'vulnerable-symbols.manifest.json');

    expect(fs.existsSync(dataFilePath)).toEqual(true);
    expect(fs.existsSync(manifestFilePath)).toEqual(true);

    const result = SymbolDatasetLoader.loadBundledDataset();
    expect(result.ok).toEqual(true);
    expect(result.dataset?.entries.length).toEqual(18);

    const rawData = fs.readFileSync(dataFilePath);
    const computedHash = crypto.createHash('sha256').update(rawData).digest('hex');

    expect(result.manifest?.sha256).toEqual(computedHash);
    expect(result.manifest?.entryCount).toEqual(18);
  });

  it('B3: total miss returns candidates[0], emits single warning across 3 calls with all directories, re-arms on resetCache', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const candidates = SymbolDatasetLoader.getBundledDataCandidates();

    const dir1 = SymbolDatasetLoader.getBundledDataDirectory();
    const dir2 = SymbolDatasetLoader.getBundledDataDirectory();
    const dir3 = SymbolDatasetLoader.getBundledDataDirectory();

    expect(dir1).toEqual(candidates[0]);
    expect(dir2).toEqual(candidates[0]);
    expect(dir3).toEqual(candidates[0]);

    // console.warn must be called exactly once across the 3 consecutive calls
    expect(warnSpy).toHaveBeenCalledTimes(1);

    const warnMessage = warnSpy.mock.calls[0]?.[0] as string;
    expect(warnMessage).toContain(
      '[WARNING] Curated vulnerable symbol dataset is unavailable. Searched directories:'
    );
    for (const c of candidates) {
      expect(warnMessage).toContain(c);
    }

    // After resetCache, warning re-arms and warns once more
    SymbolDatasetLoader.resetCache();
    const dir4 = SymbolDatasetLoader.getBundledDataDirectory();
    expect(dir4).toEqual(candidates[0]);
    expect(warnSpy).toHaveBeenCalledTimes(2);

    // loadBundledDataset fails closed gracefully without throwing
    const loadResult = SymbolDatasetLoader.loadBundledDataset();
    expect(loadResult.ok).toEqual(false);
    expect(loadResult.dataset).toEqual(null);
    expect(loadResult.error).toContain('Symbol dataset file not found');
  });

  it('B4: F6 shadow attack: untrusted project data/ cannot shadow bundled dataset or inject canary CVE', () => {
    const shadowCwd = makeTempDir('secureship-shadow-cwd-');
    const shadowDataDir = path.join(shadowCwd, 'data');
    fs.mkdirSync(shadowDataDir, { recursive: true });

    const canaryDataset = {
      version: '1.0.0',
      datasetId: 'shadow-canary-dataset',
      description: 'Decoy shadow dataset for F6 security validation',
      entries: [
        {
          id: 'CVE-0000-CANARY',
          aliases: ['GHSA-canary-test'],
          ecosystem: 'npm' as const,
          package: 'canary-shadow-pkg',
          entryPoints: [{ module: '.', export: 'evalCanary', kind: 'FUNCTION' as const }],
          triggeredOn: 'CALL' as const,
          entryPointsComplete: true,
          sourceUrls: ['https://example.com/advisories/canary'],
          fixCommitUrls: ['https://example.com/commits/canary-fix'],
          verifiedAt: '2026-10-27',
          verifiedBy: 'SecureShip Security Engineering',
          notes: 'Adversarial canary symbol entry for F6 non-shadowing verification',
        },
      ],
    };

    const canaryRaw = JSON.stringify(canaryDataset, null, 2);
    const canaryHash = crypto
      .createHash('sha256')
      .update(Buffer.from(canaryRaw, 'utf-8'))
      .digest('hex');
    const canaryManifest = {
      filename: 'vulnerable-symbols.json',
      sha256: canaryHash,
      bytes: Buffer.byteLength(canaryRaw, 'utf-8'),
      entryCount: 1,
      updatedAt: '2026-10-27T00:00:00Z',
    };

    fs.writeFileSync(path.join(shadowDataDir, 'vulnerable-symbols.json'), canaryRaw, 'utf-8');
    fs.writeFileSync(
      path.join(shadowDataDir, 'vulnerable-symbols.manifest.json'),
      JSON.stringify(canaryManifest, null, 2),
      'utf-8'
    );

    // Mock cwd to the untrusted shadow repository
    vi.spyOn(process, 'cwd').mockReturnValue(shadowCwd);
    SymbolDatasetLoader.resetCache();

    const result = SymbolDatasetLoader.loadBundledDataset();

    expect(result.ok).toEqual(true);
    // sourcePath must NOT be inside the untrusted shadow project cwd
    const normalizedSource = path.resolve(result.sourcePath || '');
    const normalizedShadow = path.resolve(shadowCwd);
    expect(normalizedSource.startsWith(normalizedShadow)).toEqual(false);

    // The dataset must NOT contain the canary CVE
    const hasCanary = result.dataset?.entries.some((e) => e.id === 'CVE-0000-CANARY');
    expect(hasCanary).toEqual(false);

    // It must load the genuine bundled dataset (18 entries)
    expect(result.dataset?.entries.length).toEqual(18);
  });

  it('B5: fallback-only case: loads dataset from cwd fallback candidate and emits security warning', () => {
    const fallbackCwd = makeTempDir('secureship-fallback-cwd-');
    const fallbackDataDir = path.join(fallbackCwd, 'data');
    fs.mkdirSync(fallbackDataDir, { recursive: true });

    // Copy genuine files to fallback directory so schema and hash verification pass
    const realDataContent = fs.readFileSync(
      path.join(reachabilityDataDir, 'vulnerable-symbols.json'),
      'utf-8'
    );
    const realManifestContent = fs.readFileSync(
      path.join(reachabilityDataDir, 'vulnerable-symbols.manifest.json'),
      'utf-8'
    );

    fs.writeFileSync(
      path.join(fallbackDataDir, 'vulnerable-symbols.json'),
      realDataContent,
      'utf-8'
    );
    fs.writeFileSync(
      path.join(fallbackDataDir, 'vulnerable-symbols.manifest.json'),
      realManifestContent,
      'utf-8'
    );

    vi.spyOn(process, 'cwd').mockReturnValue(fallbackCwd);

    const candidates = SymbolDatasetLoader.getBundledDataCandidates(realModuleDir, fallbackCwd);
    const candidate5 = candidates[4]!;

    // Mock existsSync: false for candidates 0..3, real check for candidate 4 (candidate5)
    const originalExistsSync = fs.existsSync.bind(fs);
    vi.spyOn(fs, 'existsSync').mockImplementation((p: fs.PathLike) => {
      const pStr = path.resolve(p.toString());
      if (pStr.startsWith(candidate5)) {
        return originalExistsSync(p);
      }
      return false;
    });

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    SymbolDatasetLoader.resetCache();

    const result = SymbolDatasetLoader.loadBundledDataset();

    expect(result.ok).toEqual(true);
    expect(result.sourcePath).toEqual(path.join(candidate5, 'vulnerable-symbols.json'));
    expect(result.dataset?.entries.length).toEqual(18);

    // Verify security warning regarding fallback was emitted
    const securityWarnCalls = warnSpy.mock.calls
      .map((c) => c[0] as string)
      .filter(
        (msg) =>
          msg.includes('F6 trust model') && msg.includes('NOT from the bundled package location')
      );
    expect(securityWarnCalls.length).toEqual(1);
  });

  it('B6: table-driven candidate priority: lowest-numbered existing candidate always wins', () => {
    const fakeModule = path.resolve('/mock/module/reachability/symbols');
    const fakeCwd = path.resolve('/mock/project/root');
    const candidates = SymbolDatasetLoader.getBundledDataCandidates(fakeModule, fakeCwd);

    // Sub-table 1: Candidate-k-only (for k = 0..4)
    for (let k = 0; k < candidates.length; k++) {
      SymbolDatasetLoader.resetCache();

      // Simulate only candidate k existing
      vi.spyOn(SymbolDatasetLoader, 'getBundledDataCandidates').mockReturnValue(candidates);
      vi.spyOn(fs, 'existsSync').mockImplementation((p: fs.PathLike) => {
        const pStr = path.resolve(p.toString());
        return pStr.startsWith(candidates[k]!);
      });
      vi.spyOn(console, 'warn').mockImplementation(() => {});

      const resolved = SymbolDatasetLoader.getBundledDataDirectory();
      expect(resolved).toEqual(candidates[k]);
      vi.restoreAllMocks();
    }

    // Sub-table 2: Candidate-k and candidate-(k+1) both exist -> lowest-numbered (k) wins
    for (let k = 0; k < candidates.length - 1; k++) {
      SymbolDatasetLoader.resetCache();

      vi.spyOn(SymbolDatasetLoader, 'getBundledDataCandidates').mockReturnValue(candidates);
      vi.spyOn(fs, 'existsSync').mockImplementation((p: fs.PathLike) => {
        const pStr = path.resolve(p.toString());
        return pStr.startsWith(candidates[k]!) || pStr.startsWith(candidates[k + 1]!);
      });
      vi.spyOn(console, 'warn').mockImplementation(() => {});

      const resolved = SymbolDatasetLoader.getBundledDataDirectory();
      expect(resolved).toEqual(candidates[k]);
      vi.restoreAllMocks();
    }
  });
});
