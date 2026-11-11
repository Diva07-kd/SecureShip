import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  VulnerableSymbolDatasetSchema,
  SymbolDatasetManifestSchema,
  type VulnerableSymbolDataset,
  type SymbolDatasetManifest,
} from './vulnerable-symbol.schema.js';
import { getStandaloneExecDir } from '../standalone-exec.js';

export interface DatasetLoadResult {
  ok: boolean;
  dataset: VulnerableSymbolDataset | null;
  manifest: SymbolDatasetManifest | null;
  sourcePath: string;
  error?: string;
  warning?: string;
}

const realModuleDir = path.dirname(fileURLToPath(import.meta.url));

export class SymbolDatasetLoader {
  private static cachedBundledDataset: VulnerableSymbolDataset | null = null;
  private static cachedManifest: SymbolDatasetManifest | null = null;
  private static hasWarnedUnavailable = false;

  /**
   * Returns candidate directories for bundled vulnerable symbol data in strict priority order.
   *
   * Priority Order:
   * 1. path.resolve(moduleDir, 'data')                  // Bundled CLI package: dist/data
   * 2. path.resolve(moduleDir, '../../data')            // Monorepo source layout: packages/reachability/data
   * 3. path.resolve(moduleDir, '../data')               // Reachability package dist layout
   * 4. path.resolve(cwd, 'packages/reachability/data')  // Monorepo-dev fallback
   * 5. path.resolve(cwd, 'data')                        // Monorepo-dev fallback
   *
   * Trust Model (Anti-Cheat Rule F6):
   * Candidates 4 and 5 resolve relative to process.cwd(), which in a global CLI install points
   * to untrusted user project repositories. To prevent an analyzed project from shadowing or
   * tampering with curated vulnerability data, candidate search order guarantees that bundled
   * package assets (candidates 1-3) ALWAYS take strict precedence. Candidates 4 and 5 serve
   * strictly as last-resort developer fallbacks during monorepo development.
   *
   * @param moduleDir - The directory of the executing module (defaults to real moduleDir).
   * @param cwd - The working directory (defaults to process.cwd()).
   * @returns De-duplicated list of candidate directory paths.
   */
  public static getBundledDataCandidates(
    moduleDir: string = realModuleDir,
    cwd: string = process.cwd(),
    execDir: string | null = getStandaloneExecDir()
  ): string[] {
    const raw = [
      path.resolve(moduleDir, 'data'),
      path.resolve(moduleDir, '../../data'),
      path.resolve(moduleDir, '../data'),
      ...(execDir ? [path.resolve(execDir, 'data')] : []),
      path.resolve(cwd, 'packages/reachability/data'),
      path.resolve(cwd, 'data'),
    ];

    return Array.from(new Set(raw));
  }

  /**
   * Resolves the directory containing the bundled vulnerable-symbols.json and manifest.
   * Searches candidate directories in strict priority order.
   *
   * If a cwd-based fallback candidate (4 or 5) is selected, emits a security warning indicating
   * that the dataset was not loaded from the bundled package location (F6).
   *
   * If no candidate directory contains both the dataset and manifest, emits a single warning per
   * process listing all searched directories and returns candidates[0] to allow fail-closed handling.
   */
  public static getBundledDataDirectory(execDir: string | null = getStandaloneExecDir()): string {
    const candidates = this.getBundledDataCandidates(realModuleDir, process.cwd(), execDir);

    const trustedCandidates = new Set([
      path.resolve(realModuleDir, 'data'),
      path.resolve(realModuleDir, '../../data'),
      path.resolve(realModuleDir, '../data'),
      ...(execDir ? [path.resolve(execDir, 'data')] : []),
    ]);

    for (const dir of candidates) {
      const dataFile = path.join(dir, 'vulnerable-symbols.json');
      const manifestFile = path.join(dir, 'vulnerable-symbols.manifest.json');
      if (fs.existsSync(dataFile) && fs.existsSync(manifestFile)) {
        if (!trustedCandidates.has(dir)) {
          console.warn(
            `[SECURITY WARNING] Symbol dataset resolved from fallback directory '${dir}'. Note: this dataset is NOT from the bundled package location (F6 trust model).`
          );
        }
        return dir;
      }
    }

    if (!this.hasWarnedUnavailable) {
      this.hasWarnedUnavailable = true;
      console.warn(
        `[WARNING] Curated vulnerable symbol dataset is unavailable. Searched directories:\n${candidates.map((d) => `  - ${d}`).join('\n')}`
      );
    }

    return candidates[0]!;
  }

  /**
   * Checks whether a path points to an untrusted repository-resident location (e.g. .secureship/ or inside projectRoot).
   * Anti-Cheat Rule F6:
   * A repo-resident dataset, config key or .secureship/ file can never add symbols, enable pruning,
   * or change confidence (ignored with a warning).
   */
  public static isRepoResidentPath(candidatePath: string, projectRoot?: string): boolean {
    const normalized = path.resolve(candidatePath).replace(/\\/g, '/');
    if (normalized.includes('/.secureship/')) {
      return true;
    }
    if (projectRoot) {
      const rootNormalized = path.resolve(projectRoot).replace(/\\/g, '/');
      if (normalized.startsWith(rootNormalized + '/')) {
        return true;
      }
    }
    return false;
  }

  /**
   * Loads and cryptographically verifies the bundled vulnerable symbol dataset.
   * Fail closed: any mismatch or schema invalidity causes the dataset to be ignored with a warning.
   */
  public static loadBundledDataset(): DatasetLoadResult {
    if (this.cachedBundledDataset && this.cachedManifest) {
      return {
        ok: true,
        dataset: this.cachedBundledDataset,
        manifest: this.cachedManifest,
        sourcePath: path.join(this.getBundledDataDirectory(), 'vulnerable-symbols.json'),
      };
    }

    const dataDir = this.getBundledDataDirectory();
    const dataPath = path.join(dataDir, 'vulnerable-symbols.json');
    const manifestPath = path.join(dataDir, 'vulnerable-symbols.manifest.json');

    const result = this.loadAndVerifyDataset(dataPath, manifestPath);
    if (result.ok && result.dataset && result.manifest) {
      this.cachedBundledDataset = result.dataset;
      this.cachedManifest = result.manifest;
    }
    return result;
  }

  /**
   * Loads dataset from either a custom user-level path or the default bundled path.
   * If a custom path is specified, verifies it is NOT repository-resident (F6).
   */
  public static loadDataset(customPath?: string, projectRoot?: string): DatasetLoadResult {
    if (!customPath) {
      return this.loadBundledDataset();
    }

    const resolvedCustom = path.resolve(customPath);
    if (this.isRepoResidentPath(resolvedCustom, projectRoot)) {
      const warning = `[SECURITY WARNING] Symbol dataset at '${customPath}' is located inside the repository or .secureship/ directory. Datasets may only be loaded from bundled package data, user-level config (~/.secureship/), or CLI flags outside the analyzed repository. Ignoring untrusted repo-resident dataset.`;
      console.warn(warning);
      return {
        ok: false,
        dataset: null,
        manifest: null,
        sourcePath: resolvedCustom,
        warning,
        error: 'Repo-resident dataset rejected by trust model',
      };
    }

    return this.loadAndVerifyDataset(resolvedCustom);
  }

  /**
   * Loads a dataset file, validates SHA-256 against manifest (if present), and validates strict Zod schema.
   */
  public static loadAndVerifyDataset(
    dataPath: string,
    explicitManifestPath?: string
  ): DatasetLoadResult {
    if (!fs.existsSync(dataPath)) {
      const error = `Symbol dataset file not found at '${dataPath}'`;
      console.warn(`[WARNING] ${error}`);
      return { ok: false, dataset: null, manifest: null, sourcePath: dataPath, error };
    }

    let rawBytes: Buffer;
    try {
      rawBytes = fs.readFileSync(dataPath);
    } catch (err: unknown) {
      const error = `Failed to read dataset file at '${dataPath}': ${err instanceof Error ? err.message : String(err)}`;
      console.warn(`[WARNING] ${error}`);
      return { ok: false, dataset: null, manifest: null, sourcePath: dataPath, error };
    }

    const actualHash = crypto.createHash('sha256').update(rawBytes).digest('hex');

    // Attempt to locate and verify manifest
    const manifestPath =
      explicitManifestPath ||
      path.join(path.dirname(dataPath), `${path.basename(dataPath, '.json')}.manifest.json`);

    let manifest: SymbolDatasetManifest | null = null;
    if (fs.existsSync(manifestPath)) {
      try {
        const manifestRaw = fs.readFileSync(manifestPath, 'utf-8');
        const parsedManifestJson = JSON.parse(manifestRaw);
        const manifestValidation = SymbolDatasetManifestSchema.safeParse(parsedManifestJson);
        if (!manifestValidation.success) {
          const error = `Invalid manifest format at '${manifestPath}': ${manifestValidation.error.message}`;
          console.warn(`[SECURITY WARNING] ${error}. Symbol dataset ignored (fail-closed).`);
          return { ok: false, dataset: null, manifest: null, sourcePath: dataPath, error };
        }
        manifest = manifestValidation.data;

        if (manifest.sha256 !== actualHash) {
          const error = `Integrity check failed for dataset at '${dataPath}': expected SHA-256 '${manifest.sha256}', got '${actualHash}'`;
          console.warn(
            `[SECURITY WARNING] ${error}. Tampered or corrupted dataset ignored (fail-closed).`
          );
          return { ok: false, dataset: null, manifest, sourcePath: dataPath, error };
        }
      } catch (err: unknown) {
        const error = `Failed to parse manifest at '${manifestPath}': ${err instanceof Error ? err.message : String(err)}`;
        console.warn(`[SECURITY WARNING] ${error}. Symbol dataset ignored (fail-closed).`);
        return { ok: false, dataset: null, manifest: null, sourcePath: dataPath, error };
      }
    }

    // Parse and validate JSON content
    let parsedData: unknown;
    try {
      parsedData = JSON.parse(rawBytes.toString('utf-8'));
    } catch (err: unknown) {
      const error = `Invalid JSON syntax in dataset at '${dataPath}': ${err instanceof Error ? err.message : String(err)}`;
      console.warn(`[WARNING] ${error}. Symbol dataset ignored (fail-closed).`);
      return { ok: false, dataset: null, manifest, sourcePath: dataPath, error };
    }

    const schemaValidation = VulnerableSymbolDatasetSchema.safeParse(parsedData);
    if (!schemaValidation.success) {
      const error = `Dataset schema validation failed for '${dataPath}': ${schemaValidation.error.message}`;
      console.warn(`[WARNING] ${error}. Symbol dataset ignored (fail-closed).`);
      return { ok: false, dataset: null, manifest, sourcePath: dataPath, error };
    }

    return {
      ok: true,
      dataset: schemaValidation.data,
      manifest,
      sourcePath: dataPath,
    };
  }

  /**
   * Resets the cached dataset and warning guards (useful for testing).
   */
  public static resetCache(): void {
    this.cachedBundledDataset = null;
    this.cachedManifest = null;
    this.hasWarnedUnavailable = false;
  }
}
