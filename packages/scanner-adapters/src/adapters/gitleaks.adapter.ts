import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
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

export interface GitleaksAdapterConfig {
  binaryOverride?: string;
}

export class GitleaksAdapter implements IScannerAdapter {
  public readonly name: ScannerName = 'gitleaks';
  public readonly category: FindingCategory = 'SECRET';
  private readonly config: GitleaksAdapterConfig;

  constructor(config: GitleaksAdapterConfig = {}) {
    this.config = config;
  }

  private resolveBinary(targetDir: string = process.cwd()): string | null {
    return BinaryResolver.resolve(
      'gitleaks',
      targetDir,
      this.config.binaryOverride ? { gitleaks: this.config.binaryOverride } : undefined
    );
  }

  public async isAvailable(): Promise<boolean> {
    return this.resolveBinary() !== null;
  }

  public async version(): Promise<string> {
    const bin = this.resolveBinary();
    if (!bin) return 'Not installed';

    try {
      const res = await SafeProcessRunner.run(bin, ['version'], {
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

  public supportsProject(_profile: ProjectProfile): boolean {
    // Secret scanning applies to all projects
    return true;
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
        errorMessage: `Gitleaks executable not found on system PATH. Install hint: ${getInstallHint('gitleaks')}`,
      };
    }

    let tempDir: string | null = null;
    try {
      tempDir = mkdtempSync(path.join(tmpdir(), 'secureship-gitleaks-'));
    } catch {
      tempDir = path.join(tmpdir(), `secureship-gitleaks-${Date.now()}`);
      mkdirSync(tempDir, { recursive: true });
    }

    const sarifOutput = path.join(tempDir, 'results.sarif');

    const args: string[] = [
      'dir',
      targetDir,
      '--report-format',
      'sarif',
      '--report-path',
      sarifOutput,
      '--redact',
      '--no-banner',
      '--exit-code',
      '0',
    ];

    const allowedEnv = ['PATH', 'PATHEXT', 'TEMP', 'TMP', 'HOME', 'USERPROFILE'];

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
          errorMessage: `Gitleaks secret scanner timed out after ${options.timeoutMs ?? 60_000}ms.`,
        };
      }

      // Check if SARIF was generated
      if (existsSync(sarifOutput)) {
        try {
          const parsed = SarifParser.parseFile(sarifOutput, {
            scannerName: this.name,
            category: 'SECRET',
            targetDir,
            defaultConfidence: 'HIGH',
          });

          // Extra safety layer: Redact all findings via SecretRedactor
          const sanitizedFindings = parsed.findings.map((f) => ({
            ...f,
            title: SecretRedactor.redactText(f.title),
            description: SecretRedactor.redactText(f.description),
            location: {
              ...f.location,
              redactedSnippet: f.location.redactedSnippet
                ? SecretRedactor.redactText(f.location.redactedSnippet)
                : undefined,
            },
          }));

          return {
            scannerName: this.name,
            status: 'SUCCESS',
            findings: sanitizedFindings,
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
            errorMessage: `Failed to parse Gitleaks SARIF output: ${
              parseErr instanceof Error ? parseErr.message : String(parseErr)
            }`,
          };
        }
      }

      // If exit code non-zero and no SARIF generated
      if (runResult.exitCode !== 0 && runResult.exitCode !== 1) {
        return {
          scannerName: this.name,
          status: 'ERROR',
          findings: [],
          durationMs,
          exitCode: runResult.exitCode,
          timedOut: false,
          errorMessage: `Gitleaks failed with exit code ${runResult.exitCode}: ${SecretRedactor.redactText(
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
