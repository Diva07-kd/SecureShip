import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { homedir, tmpdir } from 'node:os';
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

export interface OsvScannerAdapterConfig {
  binaryOverride?: string;
  offline?: boolean;
}

export class OsvScannerAdapter implements IScannerAdapter {
  public readonly name: ScannerName = 'osv-scanner';
  public readonly category: FindingCategory = 'SCA';
  private readonly config: OsvScannerAdapterConfig;
  private cachedVersion: string | null = null;

  constructor(config: OsvScannerAdapterConfig = {}) {
    this.config = config;
  }

  private hasLocalDbCache(): boolean {
    const customEnvCache =
      process.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY ?? process.env.OSV_SCANNER_CACHE_DIR;
    if (customEnvCache && existsSync(customEnvCache)) {
      try {
        const files = readdirSync(customEnvCache);
        if (files.length > 0) return true;
      } catch {
        return false;
      }
    }

    // Default OSV cache paths
    const home = homedir();
    const candidatePaths = [
      path.join(home, '.cache', 'osv-scanner'),
      path.join(home, 'AppData', 'Local', 'osv-scanner'),
      path.join(home, '.secureship', 'db', 'current', 'osv'),
    ];

    for (const p of candidatePaths) {
      if (existsSync(p)) {
        try {
          if (readdirSync(p).length > 0) return true;
        } catch {}
      }
    }

    return false;
  }

  private resolveBinary(targetDir: string = process.cwd()): string | null {
    return BinaryResolver.resolve(
      'osv-scanner',
      targetDir,
      this.config.binaryOverride ? { 'osv-scanner': this.config.binaryOverride } : undefined
    );
  }

  public async isAvailable(): Promise<boolean> {
    return this.resolveBinary() !== null;
  }

  public async version(): Promise<string> {
    if (this.cachedVersion) return this.cachedVersion;
    const bin = this.resolveBinary();
    if (!bin) return 'Not installed';

    try {
      const res = await SafeProcessRunner.run(bin, ['--version'], {
        timeoutMs: 5000,
      });
      if (res.exitCode === 0 && res.stdout.trim()) {
        const v = extractCleanSemver(res.stdout);
        this.cachedVersion = v;
        return v;
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
      profile.recommendedScanners.includes('osv-scanner')
    );
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
        errorMessage: `osv-scanner executable not found on system PATH. Install hint: ${getInstallHint('osv-scanner')}`,
      };
    }

    const isOffline = this.config.offline ?? false;
    if (isOffline && !this.hasLocalDbCache()) {
      return {
        scannerName: this.name,
        status: 'PARTIAL_FAILURE',
        findings: [],
        durationMs: Date.now() - startTime,
        exitCode: null,
        timedOut: false,
        errorMessage:
          'osv-scanner is operating in offline mode, but no cached vulnerability database was found at the local cache path. Run "secureship import-offline" or specify a valid OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY.',
      };
    }

    let tempDir: string | null = null;
    try {
      tempDir = mkdtempSync(path.join(tmpdir(), 'secureship-osv-'));
    } catch {
      tempDir = path.join(tmpdir(), `secureship-osv-${Date.now()}`);
      mkdirSync(tempDir, { recursive: true });
    }

    const sarifOutput = path.join(tempDir, 'results.sarif');

    // Detect if v2 or v1 syntax: v2 uses `scan`, v1 uses direct recursive `-r`
    const ver = await this.version();
    const isV2 = ver.includes('2.') || ver.startsWith('2.');

    const args: string[] = [];
    if (isV2) {
      args.push(
        'scan',
        'source',
        '-r',
        targetDir,
        '--format',
        'sarif',
        '--output-file',
        sarifOutput
      );
      if (this.config.offline) {
        args.push('--offline', '--offline-vulnerabilities');
      }
    } else {
      // v1 syntax
      args.push('--format', 'sarif', '--output', sarifOutput);
      if (this.config.offline) {
        args.push('--offline');
      }
      args.push('-r', targetDir);
    }

    const allowedEnv = [
      'PATH',
      'PATHEXT',
      'TEMP',
      'TMP',
      'HOME',
      'USERPROFILE',
      'APPDATA',
      'LOCALAPPDATA',
      'OSV_SCANNER_CACHE_DIR',
      'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY',
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
          errorMessage: `osv-scanner timed out after ${options.timeoutMs ?? 60_000}ms.`,
        };
      }

      let hasSarifFile = false;
      try {
        hasSarifFile = existsSync(sarifOutput) && statSync(sarifOutput).size > 0;
      } catch {
        hasSarifFile = false;
      }

      // In case osv-scanner printed SARIF to stdout instead of --output file
      if (!hasSarifFile && runResult.stdout.includes('"runs"')) {
        try {
          writeFileSync(sarifOutput, runResult.stdout, 'utf-8');
          hasSarifFile = true;
        } catch {
          // Ignored
        }
      }

      if (hasSarifFile) {
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
            errorMessage: `Failed to parse osv-scanner SARIF output: ${
              parseErr instanceof Error ? parseErr.message : String(parseErr)
            }`,
          };
        }
      }

      // Exit code 0, 1, or 128 ("No package sources found") with no SARIF file
      const noSourcesFound =
        (runResult.stderr || runResult.stdout).includes('No package sources found') ||
        (runResult.exitCode === 128 &&
          (runResult.stderr || runResult.stdout).includes('No package sources'));

      if (runResult.exitCode !== 0 && runResult.exitCode !== 1 && !noSourcesFound) {
        return {
          scannerName: this.name,
          status: 'ERROR',
          findings: [],
          durationMs,
          exitCode: runResult.exitCode,
          timedOut: false,
          errorMessage: `osv-scanner failed with exit code ${runResult.exitCode}: ${SecretRedactor.redactText(
            runResult.stderr || runResult.stdout
          )}`,
        };
      }

      if (this.config.offline && !this.hasLocalDbCache()) {
        return {
          scannerName: this.name,
          status: 'PARTIAL_FAILURE',
          findings: [],
          durationMs,
          exitCode: runResult.exitCode,
          timedOut: false,
          errorMessage:
            'osv-scanner executed in offline mode without a valid local vulnerability database; cannot verify clean status.',
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
