import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { EventEmitter } from 'node:events';
import { describe, expect, it, vi, beforeEach } from 'vitest';

const mockSpawn = vi.fn();

vi.mock('node:child_process', () => ({
  spawn: (...args: unknown[]) => mockSpawn(...args),
}));

import { buildChildEnv, runScan, runStatusCheck } from '../src/cli/cli-runner.js';

interface MockChildProcess extends EventEmitter {
  stdout: EventEmitter;
  stderr: EventEmitter;
  kill: ReturnType<typeof vi.fn>;
}

function createMockChild(): MockChildProcess {
  const child = new EventEmitter() as MockChildProcess;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = vi.fn();
  return child;
}

describe('cli-runner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('runScan parses valid JSON output file and returns ExtScanReport', async () => {
    mockSpawn.mockImplementation((_cmd: string, args: string[]) => {
      const child = createMockChild();
      process.nextTick(() => {
        const outIdx = args.indexOf('--output');
        if (outIdx >= 0 && args[outIdx + 1]) {
          const outFile = args[outIdx + 1];
          if (outFile) {
            const mockReport = {
              schemaVersion: '1.2',
              target: '/workspace',
              findings: [
                {
                  id: 'f-1',
                  fingerprint: '1'.repeat(64),
                  ruleId: 'TEST-01',
                  severity: 'HIGH',
                  scannerName: 'opengrep',
                  category: 'SAST',
                  title: 'Test finding',
                  description: 'Finding description',
                  location: { filePath: 'src/a.ts', startLine: 1, endLine: 1 },
                },
              ],
              summary: {
                totalRaw: 1,
                totalReported: 1,
                totalSuppressed: 0,
                bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
                byCategory: {},
              },
            };
            fs.writeFileSync(outFile, JSON.stringify(mockReport));
          }
        }
        child.emit('close', 0);
      });
      return child;
    });

    const result = await runScan('secureship', '/workspace');

    expect(result).not.toBeNull();
    expect(result?.schemaVersion).toBe('1.2');
    expect(Array.isArray(result?.findings)).toBe(true);
    expect(result?.findings).toHaveLength(1);
    const firstFinding = result?.findings[0];
    expect(firstFinding?.ruleId).toBe('TEST-01');
  });

  it('runScan returns null when AbortSignal fires before close event', async () => {
    mockSpawn.mockImplementation(() => {
      // Never emits 'close'
      return createMockChild();
    });

    const ac = new AbortController();
    const scanPromise = runScan('secureship', '/workspace', ac.signal);

    ac.abort();
    const result = await scanPromise;

    expect(result).toBeNull();
  });

  it('runScan returns empty report for exit code 0 with no output file', async () => {
    mockSpawn.mockImplementation(() => {
      const child = createMockChild();
      process.nextTick(() => {
        // Exit 0 without creating the output file
        child.emit('close', 0);
      });
      return child;
    });

    const result = await runScan('secureship', '/workspace');

    expect(result).not.toBeNull();
    expect(result?.findings).toHaveLength(0);
    expect(result?.summary.totalReported).toBe(0);
  });

  it('runScan returns null for exit code 2 with no output file', async () => {
    mockSpawn.mockImplementation(() => {
      const child = createMockChild();
      process.nextTick(() => {
        // Abnormal exit code 2
        child.emit('close', 2);
      });
      return child;
    });

    const result = await runScan('secureship', '/workspace');

    expect(result).toBeNull();
  });

  it('buildChildEnv prepends ~/.secureship/bin to PATH', async () => {
    const expectedBin = path.join(os.homedir(), '.secureship', 'bin');
    const env = buildChildEnv();

    expect(env.PATH).toBeDefined();
    expect(env.PATH?.startsWith(expectedBin)).toBe(true);

    let capturedEnv: NodeJS.ProcessEnv | undefined;
    mockSpawn.mockImplementation(
      (_cmd: string, _args: string[], options: { env: NodeJS.ProcessEnv }) => {
        capturedEnv = options.env;
        const child = createMockChild();
        process.nextTick(() => child.emit('close', 0));
        return child;
      }
    );

    await runScan('secureship', '/workspace');
    expect(capturedEnv?.PATH?.startsWith(expectedBin)).toBe(true);
  });

  it('runStatusCheck returns parsed ExtCliStatus on success', async () => {
    mockSpawn.mockImplementation(() => {
      const child = createMockChild();
      process.nextTick(() => {
        child.stdout.emit(
          'data',
          JSON.stringify({
            tier: 'PRO_TEAM',
            status: 'ACTIVE',
            email: 'dev@secureship.dev',
          })
        );
        child.emit('close', 0);
      });
      return child;
    });

    const status = await runStatusCheck('secureship', '/workspace');

    expect(status).not.toBeNull();
    expect(status?.tier).toBe('PRO_TEAM');
    expect(status?.status).toBe('ACTIVE');
  });
});
