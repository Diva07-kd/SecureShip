import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import type {
  FindingCategory,
  IScannerAdapter,
  ProjectProfile,
  ScanExecutionResult,
  ScanOptions,
  ScannerName,
  Severity,
} from '@secureship/contracts';
import { SafeProcessRunner, SecretRedactor } from '@secureship/core-engine';
import { BinaryResolver } from '../binary-resolver.js';
import { SarifParser } from '../sarif/sarif-parser.js';
import { getInstallHint } from '../supported-versions.js';
import { extractCleanSemver } from '../semver-extractor.js';

export interface CheckovAdapterConfig {
  binaryOverride?: string;
  offline?: boolean;
  defaultSeverity?: Severity;
}

export interface CheckovExecution {
  executable: string;
  argsPrefix: string[];
}

export class CheckovAdapter implements IScannerAdapter {
  public readonly name: ScannerName = 'checkov';
  public readonly category: FindingCategory = 'IAC';
  private readonly config: CheckovAdapterConfig;

  constructor(config: CheckovAdapterConfig = {}) {
    this.config = config;
  }

  public resolveExecution(targetDir: string = process.cwd()): CheckovExecution | null {
    let resolvedPath: string | null = null;
    if (this.config.binaryOverride) {
      if (existsSync(this.config.binaryOverride)) {
        BinaryResolver.assertNotInsideTarget(this.config.binaryOverride, targetDir);
        resolvedPath = this.config.binaryOverride;
      } else {
        return null;
      }
    } else {
      resolvedPath = BinaryResolver.resolve('checkov', targetDir);
    }

    if (resolvedPath) {
      const lower = resolvedPath.toLowerCase();
      if (lower.endsWith('.cmd') || lower.endsWith('.bat')) {
        // Run checkov as python -m checkov.main
        const py =
          BinaryResolver.resolve('python', targetDir) ??
          BinaryResolver.resolve('python3', targetDir);
        if (py) {
          return { executable: py, argsPrefix: ['-m', 'checkov.main'] };
        }
        return null;
      }
      return { executable: path.resolve(resolvedPath), argsPrefix: [] };
    }

    // Fallback: run via python -m checkov.main if python is present
    const py =
      BinaryResolver.resolve('python', targetDir) ?? BinaryResolver.resolve('python3', targetDir);
    if (py) {
      return { executable: py, argsPrefix: ['-m', 'checkov.main'] };
    }

    return null;
  }

  public resolveBinary(targetDir: string = process.cwd()): string | null {
    const exec = this.resolveExecution(targetDir);
    return exec?.executable ?? null;
  }

  public async isAvailable(): Promise<boolean> {
    const exec = this.resolveExecution();
    if (!exec) return false;
    if (exec.argsPrefix.includes('checkov.main')) {
      try {
        const res = await SafeProcessRunner.run(
          exec.executable,
          [...exec.argsPrefix, '--version'],
          {
            timeoutMs: 15_000,
          }
        );
        return res.exitCode === 0;
      } catch {
        return false;
      }
    }
    return true;
  }

  public async version(): Promise<string> {
    const exec = this.resolveExecution();
    if (!exec) return 'Not installed';

    try {
      const res = await SafeProcessRunner.run(exec.executable, [...exec.argsPrefix, '--version'], {
        timeoutMs: 15_000,
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
    return profile.iacManifests.length > 0 || profile.recommendedScanners.includes('checkov');
  }

  public async scan(targetDir: string, options: ScanOptions = {}): Promise<ScanExecutionResult> {
    const startTime = Date.now();
    const exec = this.resolveExecution(targetDir);

    if (!exec) {
      return {
        scannerName: this.name,
        status: 'TOOL_MISSING',
        findings: [],
        durationMs: Date.now() - startTime,
        exitCode: null,
        timedOut: false,
        errorMessage: `Checkov executable not found on system PATH. Install hint: ${getInstallHint('checkov')}`,
      };
    }

    let tempDir: string | null = null;
    try {
      tempDir = mkdtempSync(path.join(tmpdir(), 'secureship-checkov-'));
    } catch {
      tempDir = path.join(tmpdir(), `secureship-checkov-${Date.now()}`);
      mkdirSync(tempDir, { recursive: true });
    }

    const args: string[] = [
      '-d',
      targetDir,
      '--framework',
      'terraform,dockerfile,kubernetes',
      '--output',
      'sarif',
      '--output-file-path',
      tempDir,
      '--soft-fail',
      '--quiet',
      '--compact',
    ];

    if (this.config.offline) {
      args.push('--skip-download');
    }

    const allowedEnv = [
      'PATH',
      'PATHEXT',
      'TEMP',
      'TMP',
      'HOME',
      'USERPROFILE',
      'CHECKOV_CACHE_DIR',
    ];

    try {
      const runResult = await SafeProcessRunner.run(
        exec.executable,
        [...exec.argsPrefix, ...args],
        {
          cwd: targetDir,
          timeoutMs: options.timeoutMs ?? 60_000,
          maxBufferBytes: options.maxBufferBytes,
          allowedEnvVars: allowedEnv,
        }
      );

      const durationMs = Date.now() - startTime;

      if (runResult.timedOut) {
        return {
          scannerName: this.name,
          status: 'TIMEOUT',
          findings: [],
          durationMs,
          exitCode: runResult.exitCode,
          timedOut: true,
          errorMessage: `Checkov scanner timed out after ${options.timeoutMs ?? 60_000}ms.`,
        };
      }

      // Checkov produces results_sarif.sarif or similar in tempDir
      let sarifFile: string | null = null;
      if (existsSync(tempDir)) {
        const files = readdirSync(tempDir);
        for (const f of files) {
          if (f.endsWith('.sarif')) {
            sarifFile = path.join(tempDir, f);
            break;
          }
        }
      }

      if (sarifFile && existsSync(sarifFile)) {
        try {
          const parsed = SarifParser.parseFile(sarifFile, {
            scannerName: this.name,
            category: 'IAC',
            targetDir,
            defaultConfidence: 'MEDIUM',
            defaultSeverity: this.config.defaultSeverity ?? 'MEDIUM',
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
            errorMessage: `Failed to parse Checkov SARIF output: ${
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
          errorMessage: `Checkov failed with exit code ${runResult.exitCode}: ${SecretRedactor.redactText(
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
