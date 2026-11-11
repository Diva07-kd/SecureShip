import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { platform, tmpdir, homedir } from 'node:os';
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

export interface TrivyAdapterConfig {
  binaryOverride?: string;
  cacheDir?: string;
  offline?: boolean;
}

export class TrivyAdapter implements IScannerAdapter {
  public readonly name: ScannerName = 'trivy';
  public readonly category: FindingCategory = 'SCA';
  private readonly config: TrivyAdapterConfig;
  private static readonly isWindows = platform() === 'win32';

  constructor(config: TrivyAdapterConfig = {}) {
    this.config = config;
  }

  private resolveBinary(targetDir: string = process.cwd()): string | null {
    return BinaryResolver.resolve(
      'trivy',
      targetDir,
      this.config.binaryOverride ? { trivy: this.config.binaryOverride } : undefined
    );
  }

  public async isAvailable(): Promise<boolean> {
    return this.resolveBinary() !== null;
  }

  public async version(): Promise<string> {
    const bin = this.resolveBinary();
    if (!bin) return 'Not installed';

    try {
      const res = await SafeProcessRunner.run(bin, ['--version'], {
        timeoutMs: 5000,
      });
      if (res.exitCode === 0 && res.stdout.trim()) {
        return extractCleanSemver(res.stdout);
      }
    } catch {
      // Ignored
    }
    return 'Unknown';
  }

  public supportsProject(profile: ProjectProfile): boolean {
    return (
      profile.lockfiles.length > 0 ||
      profile.packageManagers.length > 0 ||
      profile.iacManifests.length > 0 ||
      profile.recommendedScanners.includes('trivy')
    );
  }

  /**
   * Checks if local Trivy vulnerability database cache exists.
   */
  public hasLocalDbCache(): boolean {
    if (this.config.cacheDir) {
      const dbPath = path.join(this.config.cacheDir, 'db', 'trivy.db');
      return existsSync(dbPath);
    }

    const customEnvCache = process.env.TRIVY_CACHE_DIR;
    if (customEnvCache && existsSync(path.join(customEnvCache, 'db', 'trivy.db'))) {
      return true;
    }

    // Default Trivy cache paths
    if (TrivyAdapter.isWindows) {
      const localAppData = process.env.LOCALAPPDATA ?? path.join(homedir(), 'AppData', 'Local');
      const winDbPath = path.join(localAppData, 'trivy', 'db', 'trivy.db');
      if (existsSync(winDbPath)) return true;
    } else {
      const posixDbPath = path.join(homedir(), '.cache', 'trivy', 'db', 'trivy.db');
      if (existsSync(posixDbPath)) return true;
    }

    return false;
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
        errorMessage: `Trivy executable not found on system PATH. Install hint: ${getInstallHint('trivy')}`,
      };
    }

    const isOffline = this.config.offline ?? false;

    // Amendment 8: If offline with --skip-db-update and no cache exists, return actionable PARTIAL_FAILURE
    if (isOffline && !this.hasLocalDbCache()) {
      return {
        scannerName: this.name,
        status: 'PARTIAL_FAILURE',
        findings: [],
        durationMs: Date.now() - startTime,
        exitCode: null,
        timedOut: false,
        errorMessage:
          'Trivy is operating in offline mode with --skip-db-update, but no cached vulnerability database (trivy.db) was found at the local cache path. Run "trivy image --download-db-only" or disable --offline mode to initialize the local vulnerability database cache.',
      };
    }

    let tempDir: string | null = null;
    try {
      tempDir = mkdtempSync(path.join(tmpdir(), 'secureship-trivy-'));
    } catch {
      tempDir = path.join(tmpdir(), `secureship-trivy-${Date.now()}`);
      mkdirSync(tempDir, { recursive: true });
    }

    const sarifOutput = path.join(tempDir, 'results.sarif');

    // Disable secret scanning to avoid duplicate findings with Gitleaks
    const args: string[] = [
      'fs',
      '--scanners',
      'vuln,misconfig',
      '--format',
      'sarif',
      '--output',
      sarifOutput,
    ];

    if (isOffline) {
      args.push('--offline-scan', '--skip-db-update', '--skip-check-update');
    }

    if (this.config.cacheDir) {
      args.push('--cache-dir', this.config.cacheDir);
    }

    args.push(targetDir);

    const allowedEnv = [
      'PATH',
      'PATHEXT',
      'TEMP',
      'TMP',
      'HOME',
      'USERPROFILE',
      'LOCALAPPDATA',
      'APPDATA',
      'TRIVY_CACHE_DIR',
    ];

    try {
      const runResult = await SafeProcessRunner.run(bin, args, {
        cwd: targetDir,
        timeoutMs: options.timeoutMs ?? 60_000,
        maxBufferBytes: options.maxBufferBytes,
        allowedEnvVars: allowedEnv,
      });

      const durationMs = Date.now() - startTime;

      if (runResult.timedOut) {
        return {
          scannerName: this.name,
          status: 'TIMEOUT',
          findings: [],
          durationMs,
          exitCode: runResult.exitCode,
          timedOut: true,
          errorMessage: `Trivy scanner timed out after ${options.timeoutMs ?? 60_000}ms.`,
        };
      }

      if (existsSync(sarifOutput)) {
        try {
          const parsed = SarifParser.parseFile(sarifOutput, {
            scannerName: this.name,
            category: 'SCA',
            targetDir,
            defaultConfidence: 'HIGH',
          });

          return {
            scannerName: this.name,
            status: 'SUCCESS',
            findings: parsed.findings,
            durationMs,
            exitCode: runResult.exitCode,
            timedOut: false,
            rawOutputRedacted: SecretRedactor.redactText(runResult.stdout.slice(0, 1000)),
          };
        } catch (parseErr: unknown) {
          return {
            scannerName: this.name,
            status: 'PARTIAL_FAILURE',
            findings: [],
            durationMs,
            exitCode: runResult.exitCode,
            timedOut: false,
            errorMessage: `Failed to parse Trivy SARIF output: ${
              parseErr instanceof Error ? parseErr.message : String(parseErr)
            }`,
          };
        }
      }

      if (runResult.exitCode !== 0) {
        return {
          scannerName: this.name,
          status: 'ERROR',
          findings: [],
          durationMs,
          exitCode: runResult.exitCode,
          timedOut: false,
          errorMessage: `Trivy failed with exit code ${runResult.exitCode}: ${SecretRedactor.redactText(
            runResult.stderr || runResult.stdout
          )}`,
        };
      }

      return {
        scannerName: this.name,
        status: 'SUCCESS',
        findings: [],
        durationMs,
        exitCode: runResult.exitCode,
        timedOut: false,
      };
    } catch (err: unknown) {
      return {
        scannerName: this.name,
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
          // Cleanup
        }
      }
    }
  }
}
