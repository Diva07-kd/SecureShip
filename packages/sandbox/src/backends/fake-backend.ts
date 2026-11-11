import crypto from 'node:crypto';
import {
  type ISandboxBackend,
  type SandboxRunOptions,
  type SandboxRunResult,
} from './sandbox-backend.interface.js';

export interface ScriptedFakeResponse {
  exitCode?: number | null;
  timedOut?: boolean;
  stdout?: string;
  stderr?: string;
}

export class FakeSandboxBackend implements ISandboxBackend {
  public readonly name = 'fake';
  public readonly recordedRuns: Array<{
    command: string;
    argv: string[];
    options: SandboxRunOptions;
  }> = [];

  private defaultResponse: ScriptedFakeResponse = {
    exitCode: 0,
    timedOut: false,
    stdout: 'fake execution passed',
    stderr: '',
  };

  private scriptedResponses: Map<string, ScriptedFakeResponse> = new Map();

  constructor(options?: { defaultResponse?: ScriptedFakeResponse }) {
    if (options?.defaultResponse) {
      this.setDefaultResponse(options.defaultResponse);
    }
  }

  public setDefaultResponse(resp: ScriptedFakeResponse): void {
    this.defaultResponse = { ...this.defaultResponse, ...resp };
  }

  public scriptResponse(key: string, resp: ScriptedFakeResponse): void {
    this.scriptedResponses.set(key, resp);
  }

  public reset(): void {
    this.recordedRuns.length = 0;
    this.scriptedResponses.clear();
    this.defaultResponse = {
      exitCode: 0,
      timedOut: false,
      stdout: 'fake execution passed',
      stderr: '',
    };
  }

  public async isAvailable(): Promise<boolean> {
    return true;
  }

  public getMetadata(): {
    backend: 'none';
    runtime: string;
    runtimeVersion: string;
  } {
    return {
      backend: 'none',
      runtime: 'fake-runner',
      runtimeVersion: '1.0.0',
    };
  }

  public async run(
    command: string,
    args: string[],
    options: SandboxRunOptions = {}
  ): Promise<SandboxRunResult> {
    this.recordedRuns.push({ command, argv: args, options });

    const key = options.stageName ?? command;
    const resp = this.scriptedResponses.get(key) ?? this.defaultResponse;

    const exitCode = resp.exitCode !== undefined ? resp.exitCode : 0;
    const timedOut = resp.timedOut ?? false;
    const stdout = resp.stdout ?? '';
    const stderr = resp.stderr ?? '';
    const combined = stdout + '\n' + stderr;
    const outputSha256 = crypto.createHash('sha256').update(combined).digest('hex');
    const outputTail = combined.slice(-2048);

    return {
      exitCode,
      timedOut,
      durationMs: 50,
      stdout,
      stderr,
      outputSha256,
      outputTail,
      command,
      argv: args,
    };
  }

  public async cleanup(): Promise<void> {
    // No-op for fake backend
  }
}
