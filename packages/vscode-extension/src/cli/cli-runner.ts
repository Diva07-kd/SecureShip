import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import type { ExtCliStatus, ExtScanReport } from '../types/extension-types.js';

export interface RunScanOptions {
  gate2Mode?: 'annotate' | 'suppress' | 'off';
  supplyChainOnly?: boolean;
  offline?: boolean;
}

/**
 * Builds child process environment, prepending ~/.secureship/bin to PATH.
 * This ensures binaries like opengrep, gitleaks, trivy are accessible to the CLI.
 */
export function buildChildEnv(): NodeJS.ProcessEnv {
  const home = os.homedir();
  const userBin = path.join(home, '.secureship', 'bin');
  const pathDelimiter = path.delimiter;
  const currentPath = process.env.PATH || process.env.Path || '';
  const newPath = `${userBin}${pathDelimiter}${currentPath}`;
  return {
    ...process.env,
    PATH: newPath,
    Path: newPath,
  };
}

/**
 * Executes a SecureShip security scan as a child process.
 *
 * Command line:
 * `secureship scan <workspaceRoot> --output <tmpFile> --json --no-color --gate2 <mode>`
 */
export async function runScan(
  cliPath: string,
  workspaceRoot: string,
  signal?: AbortSignal,
  options?: RunScanOptions
): Promise<ExtScanReport | null> {
  if (signal?.aborted) {
    return null;
  }

  const tmpFile = path.join(
    os.tmpdir(),
    `secureship-scan-${Date.now()}-${Math.random().toString(36).slice(2, 9)}.json`
  );

  const cleanupTmp = () => {
    try {
      if (fs.existsSync(tmpFile)) {
        fs.unlinkSync(tmpFile);
      }
    } catch {
      // Ignore temporary file cleanup errors
    }
  };

  const args = [
    'scan',
    workspaceRoot,
    '--output',
    tmpFile,
    '--json',
    '--no-color',
    '--gate2',
    options?.gate2Mode ?? 'annotate',
  ];

  if (options?.supplyChainOnly) {
    args.push('--supply-chain-only');
  }
  if (options?.offline) {
    args.push('--offline');
  }

  return new Promise((resolve) => {
    let settled = false;

    const safeResolve = (value: ExtScanReport | null) => {
      if (!settled) {
        settled = true;
        cleanupTmp();
        resolve(value);
      }
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(cliPath, args, {
        cwd: workspaceRoot,
        env: buildChildEnv(),
      });
    } catch {
      safeResolve(null);
      return;
    }

    if (signal) {
      const onAbort = () => {
        try {
          child.kill('SIGTERM');
        } catch {
          // Ignore process kill errors
        }
        safeResolve(null);
      };

      if (signal.aborted) {
        onAbort();
        return;
      }

      signal.addEventListener('abort', onAbort, { once: true });
    }

    child.on('error', () => {
      safeResolve(null);
    });

    child.on('close', (code) => {
      if (settled) {
        return;
      }

      if (fs.existsSync(tmpFile)) {
        try {
          const content = fs.readFileSync(tmpFile, 'utf-8');
          const report = JSON.parse(content) as ExtScanReport;
          safeResolve(report);
        } catch {
          safeResolve(null);
        }
      } else {
        // No output file produced
        if (code === 0 || code === 1) {
          // Empty scan with no findings
          const emptyReport: ExtScanReport = {
            schemaVersion: '1.2',
            tool: { name: 'secureship', version: '1.0.0' },
            target: workspaceRoot,
            findings: [],
            summary: {
              totalRaw: 0,
              totalReported: 0,
              totalSuppressed: 0,
              bySeverity: {
                CRITICAL: 0,
                HIGH: 0,
                MEDIUM: 0,
                LOW: 0,
                INFO: 0,
              },
              byCategory: {},
            },
          };
          safeResolve(emptyReport);
        } else {
          // Exit 2+ or abnormal termination without output file
          safeResolve(null);
        }
      }
    });
  });
}

/**
 * Executes `secureship status --json` to retrieve tier and license status.
 */
export async function runStatusCheck(
  cliPath: string,
  workspaceRoot?: string
): Promise<ExtCliStatus | null> {
  return new Promise((resolve) => {
    try {
      const child = spawn(cliPath, ['status', '--json'], {
        cwd: workspaceRoot || process.cwd(),
        env: buildChildEnv(),
      });

      let stdout = '';
      child.stdout?.on('data', (chunk: Buffer | string) => {
        stdout += chunk.toString();
      });

      child.on('error', () => {
        resolve(null);
      });

      child.on('close', (code) => {
        if (code === 0 && stdout.trim()) {
          try {
            const status = JSON.parse(stdout) as ExtCliStatus;
            resolve(status);
          } catch {
            resolve(null);
          }
        } else {
          resolve(null);
        }
      });
    } catch {
      resolve(null);
    }
  });
}
