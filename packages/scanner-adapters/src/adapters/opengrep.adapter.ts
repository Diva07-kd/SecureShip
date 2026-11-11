import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import type {
  FindingCategory,
  IScannerAdapter,
  ProjectProfile,
  ScanExecutionResult,
  ScanOptions,
  ScannerName,
} from '@secureship/contracts';
import { SafeProcessRunner, SecretRedactor } from '@secureship/core-engine';
import { BinaryResolver } from '../binary-resolver.js';
import { SarifParser } from '../sarif/sarif-parser.js';
import { getInstallHint } from '../supported-versions.js';
import { extractCleanSemver } from '../semver-extractor.js';
import { getStandaloneExecDir } from '../standalone-exec.js';

/**
 * Default timeout for Opengrep SAST scanning in milliseconds (120 seconds).
 */
export const DEFAULT_OPENGREP_TIMEOUT_MS = 120_000;

/**
 * Default exclude patterns for Opengrep / Semgrep to avoid scanning huge non-source directories.
 */
export const DEFAULT_OPENGREP_EXCLUDES = [
  'node_modules',
  'node_modules/**',
  '**/node_modules/**',
  '.git',
  '.git/**',
  'dist',
  'dist/**',
  'build',
  'build/**',
  'coverage',
  'coverage/**',
  '.secureship',
  '.secureship/**',
  'venv',
  'venv/**',
  '.venv',
  '.venv/**',
  '__pycache__',
  'vendor',
  '*.min.js',
];

export interface OpengrepAdapterConfig {
  binaryOverride?: string;
  defaultRulePath?: string;
}

const defaultModuleDir = path.dirname(fileURLToPath(import.meta.url));

/**
 * Resolves the default SAST rule pack directory in strict priority order.
 *
 * Priority Order:
 * 1. config.defaultRulePath (returned as-is with no existence check)
 * 2. path.resolve(moduleDir, 'rules/secureship-sast')        // bundled: dist/rules/...
 * 3. path.resolve(moduleDir, '../rules/secureship-sast')
 * 4. path.resolve(moduleDir, '../../rules/secureship-sast')
 * 5. path.resolve(moduleDir, '../../../../rules/secureship-sast') // monorepo source-tree root (4 levels up)
 * 6. path.resolve(cwd, 'rules/secureship-sast')              // legacy fallback (even if nonexistent)
 *
 * Steps 2-5 select the first candidate for which exists() returns true.
 */
export function resolveDefaultRulePack(
  config: OpengrepAdapterConfig,
  env?: {
    moduleDir?: string;
    cwd?: string;
    exists?: (p: string) => boolean;
    execDir?: string | null;
  }
): string {
  if (config.defaultRulePath) {
    return config.defaultRulePath;
  }

  const moduleDir = env?.moduleDir ?? defaultModuleDir;
  const cwd = env?.cwd ?? process.cwd();
  const exists = env?.exists ?? existsSync;
  const execDir = env?.execDir !== undefined ? env.execDir : getStandaloneExecDir();

  const candidates = [
    path.resolve(moduleDir, 'rules/secureship-sast'),
    path.resolve(moduleDir, '../rules/secureship-sast'),
    path.resolve(moduleDir, '../../rules/secureship-sast'),
    path.resolve(moduleDir, '../../../../rules/secureship-sast'),
    ...(execDir ? [path.resolve(execDir, 'rules/secureship-sast')] : []),
  ];

  for (const candidate of candidates) {
    if (exists(candidate)) {
      return candidate;
    }
  }

  return path.resolve(cwd, 'rules/secureship-sast');
}

export class OpengrepAdapter implements IScannerAdapter {
  public readonly name: ScannerName = 'opengrep';
  public readonly category: FindingCategory = 'SAST';
  private activeBinaryName: ScannerName = 'opengrep';
  private resolvedBinaryPath: string | null = null;
  private readonly config: OpengrepAdapterConfig;
  private readonly brokenBinaries = new Set<string>();

  constructor(config: OpengrepAdapterConfig = {}) {
    this.config = config;
  }

  /**
   * Resolves binary (opengrep with semgrep fallback).
   */
  public resolveBinary(targetDir: string = process.cwd()): string | null {
    if (this.config.binaryOverride) {
      const override = BinaryResolver.resolve('opengrep', targetDir, {
        opengrep: this.config.binaryOverride,
      });
      if (override && !this.brokenBinaries.has(override)) {
        this.activeBinaryName = 'opengrep';
        this.resolvedBinaryPath = override;
        return override;
      }
      return null;
    }

    const opengrepPath = BinaryResolver.resolve('opengrep', targetDir);
    if (opengrepPath && !this.brokenBinaries.has(opengrepPath)) {
      this.activeBinaryName = 'opengrep';
      this.resolvedBinaryPath = opengrepPath;
      return opengrepPath;
    }

    const semgrepPath = BinaryResolver.resolve('semgrep', targetDir);
    if (semgrepPath && !this.brokenBinaries.has(semgrepPath)) {
      this.activeBinaryName = 'semgrep';
      this.resolvedBinaryPath = semgrepPath;
      return semgrepPath;
    }

    return null;
  }

  public async isAvailable(): Promise<boolean> {
    const bin = this.resolveBinary();
    if (!bin) return false;
    const v = await this.version();
    return v !== 'Unknown' && v !== 'Not installed';
  }

  public async version(): Promise<string> {
    let bin = this.resolveBinary();
    if (!bin) return 'Not installed';

    try {
      const res = await SafeProcessRunner.run(bin, ['--version'], {
        timeoutMs: 15_000,
      });
      if (res.exitCode === 0 && res.stdout.trim()) {
        return extractCleanSemver(res.stdout);
      }
      return 'Unknown';
    } catch {
      // Binary execution threw (e.g. Windows Smart App Control blocked with spawn UNKNOWN)
      // Record this binary as broken for this adapter and try fallback binary (semgrep)
      this.brokenBinaries.add(bin);
    }

    bin = this.resolveBinary();
    if (bin) {
      try {
        const fallbackRes = await SafeProcessRunner.run(bin, ['--version'], {
          timeoutMs: 15_000,
        });
        if (fallbackRes.exitCode === 0 && fallbackRes.stdout.trim()) {
          return extractCleanSemver(fallbackRes.stdout);
        }
      } catch {
        this.brokenBinaries.add(bin);
      }
    }

    return 'Unknown';
  }

  public supportsProject(profile: ProjectProfile): boolean {
    // Supports if any source code language detected or recommended
    return profile.languages.length > 0 || profile.recommendedScanners.includes('opengrep');
  }

  public async scan(targetDir: string, options: ScanOptions = {}): Promise<ScanExecutionResult> {
    const startTime = Date.now();
    const bin = this.resolveBinary(targetDir);

    if (!bin) {
      return {
        scannerName: this.name,
        status: 'TOOL_MISSING',
        findings: [],
        durationMs: Date.now() - startTime,
        exitCode: null,
        timedOut: false,
        errorMessage: `Neither opengrep nor semgrep executable found on system PATH. Install hint: ${getInstallHint('opengrep')}`,
      };
    }

    // Set up private temporary directory with secure permissions
    let tempDir: string | null = null;
    try {
      tempDir = mkdtempSync(path.join(tmpdir(), 'secureship-opengrep-'));
    } catch {
      // Fallback
      tempDir = path.join(tmpdir(), `secureship-opengrep-${Date.now()}`);
      mkdirSync(tempDir, { recursive: true });
    }

    const sarifOutput = path.join(tempDir, 'results.sarif');

    // Determine rule paths: default to bundled rules/secureship-sast
    const defaultPack = resolveDefaultRulePack(this.config);
    const rulePaths =
      options.rulePaths && options.rulePaths.length > 0 ? options.rulePaths : [defaultPack];

    const args: string[] = ['scan'];
    for (const r of rulePaths) {
      args.push('--config', r);
    }

    if (this.activeBinaryName === 'semgrep') {
      args.push(
        '--sarif',
        '--output',
        sarifOutput,
        '--metrics=off',
        '--disable-version-check',
        '--use-git-ignore',
        '--jobs=1'
      );
    } else {
      args.push(`--sarif-output=${sarifOutput}`, '--disable-version-check', '--use-git-ignore');
    }

    // Default excludes for non-source and huge folders
    for (const pat of DEFAULT_OPENGREP_EXCLUDES) {
      args.push(`--exclude=${pat}`);
    }

    // If incremental diff mode with specific changed files
    if (options.changedFiles && options.changedFiles.length > 0) {
      for (const file of options.changedFiles) {
        args.push('--include', file);
      }
    }

    args.push(targetDir);

    const allowedEnv = [
      'PATH',
      'PATHEXT',
      'TEMP',
      'TMP',
      'HOME',
      'USERPROFILE',
      'SEMGREP_CACHE_DIR',
      'OPENGREP_CACHE_DIR',
    ];

    const effectiveTimeoutMs = options.timeoutMs ?? DEFAULT_OPENGREP_TIMEOUT_MS;

    try {
      const runResult = await SafeProcessRunner.run(bin, args, {
        cwd: targetDir,
        timeoutMs: effectiveTimeoutMs,
        maxBufferBytes: options.maxBufferBytes,
        allowedEnvVars: allowedEnv,
      });

      const durationMs = Date.now() - startTime;

      if (runResult.timedOut) {
        return {
          scannerName: this.activeBinaryName,
          status: 'TIMEOUT',
          findings: [],
          durationMs,
          exitCode: runResult.exitCode,
          timedOut: true,
          errorMessage: `SAST scanner timed out after ${effectiveTimeoutMs}ms (use --timeout <ms> to increase).`,
        };
      }

      // Check if SARIF file was generated
      if (existsSync(sarifOutput)) {
        try {
          const parsed = SarifParser.parseFile(sarifOutput, {
            scannerName: this.activeBinaryName,
            category: 'SAST',
            targetDir,
            defaultConfidence: 'MEDIUM',
          });

          return {
            scannerName: this.activeBinaryName,
            status: 'SUCCESS',
            findings: parsed.findings,
            durationMs,
            exitCode: runResult.exitCode,
            timedOut: false,
            rawOutputRedacted: SecretRedactor.redactText(runResult.stdout.slice(0, 1000)),
          };
        } catch (parseErr: unknown) {
          return {
            scannerName: this.activeBinaryName,
            status: 'PARTIAL_FAILURE',
            findings: [],
            durationMs,
            exitCode: runResult.exitCode,
            timedOut: false,
            errorMessage: `Failed to parse SAST SARIF output: ${
              parseErr instanceof Error ? parseErr.message : String(parseErr)
            }`,
          };
        }
      }

      // If no SARIF generated and exitCode non-zero, report error
      if (runResult.exitCode !== 0) {
        return {
          scannerName: this.activeBinaryName,
          status: 'ERROR',
          findings: [],
          durationMs,
          exitCode: runResult.exitCode,
          timedOut: false,
          errorMessage: `Scanner failed with exit code ${runResult.exitCode}: ${SecretRedactor.redactText(
            runResult.stderr || runResult.stdout
          )}`,
        };
      }

      return {
        scannerName: this.activeBinaryName,
        status: 'SUCCESS',
        findings: [],
        durationMs,
        exitCode: runResult.exitCode,
        timedOut: false,
      };
    } catch (err: unknown) {
      if (bin) {
        this.brokenBinaries.add(bin);
        // Self-healing: if an alternate fallback binary is available, retry scan
        const fallbackBin = this.resolveBinary(targetDir);
        if (fallbackBin && fallbackBin !== bin) {
          return this.scan(targetDir, options);
        }
      }
      return {
        scannerName: this.activeBinaryName,
        status: 'ERROR',
        findings: [],
        durationMs: Date.now() - startTime,
        exitCode: null,
        timedOut: false,
        errorMessage: err instanceof Error ? err.message : String(err),
      };
    } finally {
      if (tempDir && existsSync(tempDir)) {
        try {
          rmSync(tempDir, { recursive: true, force: true });
        } catch {
          // Cleanup best effort
        }
      }
    }
  }
}
