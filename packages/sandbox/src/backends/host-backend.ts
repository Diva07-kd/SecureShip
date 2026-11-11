import crypto from 'node:crypto';
import fs from 'node:fs';
import type { SandboxConfig } from '@secureship/contracts';
import { SafeProcessRunner } from '../runner/safe-process-runner.js';
import { SecretRedactor } from '@secureship/context-slicer';
import {
  type ISandboxBackend,
  type SandboxRunOptions,
  type SandboxRunResult,
} from './sandbox-backend.interface.js';

export interface HostBackendOptions {
  repoDir: string;
  shadowDir: string;
  config: SandboxConfig;
}

export class HostBackend implements ISandboxBackend {
  public readonly name = 'host';
  private readonly repoDir: string;
  private readonly shadowDir: string;
  private readonly config: SandboxConfig;

  constructor(options: HostBackendOptions) {
    this.repoDir = options.repoDir;
    this.shadowDir = options.shadowDir;
    this.config = options.config;
  }

  public static computeRepoHash(repoPath: string): string {
    const real = fs.realpathSync(repoPath);
    return crypto.createHash('sha256').update(real).digest('hex');
  }

  public async isAvailable(): Promise<boolean> {
    return this.isRepoTrusted();
  }

  public isRepoTrusted(): boolean {
    const repoHash = HostBackend.computeRepoHash(this.repoDir);
    return this.config.trustedHostRepos.includes(repoHash);
  }

  public getMetadata(): {
    backend: 'host';
  } {
    return {
      backend: 'host',
    };
  }

  public async run(
    command: string,
    args: string[],
    options: SandboxRunOptions = {}
  ): Promise<SandboxRunResult> {
    if (!this.isRepoTrusted()) {
      const repoHash = HostBackend.computeRepoHash(this.repoDir);
      throw new Error(
        `Host Execution Refused: Repository at '${this.repoDir}' (hash ${repoHash.substring(0, 12)}) is not trusted for host execution. Run 'secureship sandbox trust-host' to explicitly authorize.`
      );
    }

    const limits = this.config.limits;
    const startTime = Date.now();
    const timeoutMs = options.timeoutMs ?? limits.totalTimeoutSec * 1000;
    const maxBuffer = limits.outputCapBytes;

    const allowedEnv = [
      'PATH',
      'PATHEXT',
      'TEMP',
      'TMP',
      'HOME',
      'USERPROFILE',
      'CI',
      'LANG',
      'LC_ALL',
    ];

    const hostEnv: Record<string, string> = {
      CI: '1',
      NODE_ENV: 'test',
      ...options.env,
    };

    const res = await SafeProcessRunner.run(command, args, {
      cwd: this.shadowDir,
      timeoutMs,
      maxBufferBytes: maxBuffer,
      allowedEnvVars: allowedEnv,
      env: hostEnv,
    });

    const durationMs = Date.now() - startTime;
    const banner = '--- HOST EXECUTION: NOT A SANDBOX ---\n';
    const combinedOutput = banner + (res.stdout + '\n' + res.stderr).slice(-maxBuffer);
    const redactedOutput = SecretRedactor.redactText(combinedOutput);
    const outputSha256 = crypto.createHash('sha256').update(combinedOutput).digest('hex');
    const outputTail = redactedOutput.slice(-2048);

    return {
      exitCode: res.exitCode,
      timedOut: res.timedOut,
      durationMs,
      stdout: banner + res.stdout,
      stderr: res.stderr,
      outputSha256,
      outputTail,
      command,
      argv: args,
    };
  }

  public async cleanup(): Promise<void> {
    // Process tree is managed per run
  }
}
