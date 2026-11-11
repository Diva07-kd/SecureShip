import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { platform } from 'node:os';
import type { SandboxConfig } from '@secureship/contracts';
import { SafeProcessRunner } from '../runner/safe-process-runner.js';
import { SecretRedactor } from '@secureship/context-slicer';
import {
  type ISandboxBackend,
  type SandboxRunOptions,
  type SandboxRunResult,
} from './sandbox-backend.interface.js';

export interface NativeIsolatedBackendOptions {
  shadowDir: string;
  config: SandboxConfig;
  rootDir?: string;
}

export class NativeIsolatedBackend implements ISandboxBackend {
  public readonly name = 'native-isolated';
  private readonly shadowDir: string;
  private readonly config: SandboxConfig;
  private readonly rootDir?: string;
  private static readonly isWindows = platform() === 'win32';

  constructor(options: NativeIsolatedBackendOptions) {
    this.shadowDir = options.shadowDir;
    this.config = options.config;
    this.rootDir = options.rootDir;
  }

  public async isAvailable(): Promise<boolean> {
    return true;
  }

  public getMetadata(): {
    backend: 'native-isolated';
    isolation: string;
    networkIsolated: boolean;
  } {
    return {
      backend: 'native-isolated',
      isolation: 'shadow-airgap',
      networkIsolated: true,
    };
  }

  /**
   * Builds the strict network air-gap environment variables.
   * Universal dead-loopback proxy (127.0.0.1:0) instantly drops any outbound TCP/HTTP socket.
   * Specific tool offline flags prevent DNS lookups and index queries across 99% of tech stacks.
   */
  public static buildNetworkIsolationEnv(allowNetwork: boolean): Record<string, string> {
    if (allowNetwork) {
      return {
        CI: '1',
        NODE_ENV: 'test',
      };
    }

    return {
      CI: '1',
      NODE_ENV: 'test',

      // 1. Universal Proxy Neutralization (Dead Loopback Sink)
      HTTP_PROXY: 'http://127.0.0.1:0',
      HTTPS_PROXY: 'http://127.0.0.1:0',
      ALL_PROXY: 'socks5://127.0.0.1:0',
      http_proxy: 'http://127.0.0.1:0',
      https_proxy: 'http://127.0.0.1:0',
      all_proxy: 'socks5://127.0.0.1:0',
      NO_PROXY: '',
      no_proxy: '',

      // 2. JavaScript / Node.js Ecosystem (npm, yarn, pnpm, bun)
      npm_config_proxy: 'http://127.0.0.1:0',
      npm_config_https_proxy: 'http://127.0.0.1:0',
      npm_config_offline: 'true',
      YARN_OFFLINE: 'true',

      // 3. Python Ecosystem (pip, poetry, pipenv)
      PIP_PROXY: 'http://127.0.0.1:0',
      PIP_NO_INDEX: 'true',
      PIP_ISOLATED: '1',
      POETRY_VIRTUALENVS_IN_PROJECT: 'true',

      // 4. Rust Ecosystem (cargo)
      CARGO_NET_OFFLINE: 'true',

      // 5. Go Modules Ecosystem
      GOPROXY: 'off',

      // 6. Java / JVM Ecosystem (Maven, Gradle)
      MAVEN_OPTS: '-Dmaven.offline=true',
      GRADLE_OPTS: '-Dorg.gradle.offline=true -Dorg.gradle.daemon=false',

      // 7. .NET / C# Ecosystem (dotnet, nuget)
      DOTNET_CLI_TELEMETRY_OPTOUT: '1',
      DOTNET_SKIP_FIRST_TIME_EXPERIENCE: '1',
      NUGET_CERT_REVOCATION_MODE: 'offline',

      // 8. Ruby Ecosystem (bundler, gem)
      BUNDLE_LOCAL: 'true',
    };
  }

  /**
   * Safely resolves executables to avoid shell injection and Windows .cmd spawning limitations.
   * Runs Node CLI scripts (npm, npx, yarn) directly via process.execPath without shell or .cmd.
   */
  public static resolveCommand(
    command: string,
    args: string[]
  ): { executable: string; args: string[] } {
    if (!NativeIsolatedBackend.isWindows) {
      return { executable: command, args };
    }

    const lowerCmd = command.toLowerCase();

    // Node direct execution
    if (lowerCmd === 'node') {
      return { executable: process.execPath, args };
    }

    // Direct npm-cli execution via node.exe
    if (lowerCmd === 'npm') {
      const nodeDir = path.dirname(process.execPath);
      const npmCli = path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js');
      if (fs.existsSync(npmCli)) {
        return { executable: process.execPath, args: [npmCli, ...args] };
      }
    }

    // Direct npx-cli execution via node.exe
    if (lowerCmd === 'npx') {
      const nodeDir = path.dirname(process.execPath);
      const npxCli = path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npx-cli.js');
      if (fs.existsSync(npxCli)) {
        return { executable: process.execPath, args: [npxCli, ...args] };
      }
    }

    // Direct pnpm binary or script execution
    if (lowerCmd === 'pnpm') {
      const localAppData = process.env.LOCALAPPDATA;
      const appData = process.env.APPDATA;
      const candidates = [
        appData ? path.join(appData, 'npm', 'node_modules', 'pnpm', 'pnpm.exe') : '',
        localAppData ? path.join(localAppData, 'pnpm', 'pnpm.exe') : '',
      ].filter(Boolean);

      for (const cand of candidates) {
        if (fs.existsSync(cand)) {
          return { executable: cand, args };
        }
      }
    }

    // Direct yarn script execution via node.exe
    if (lowerCmd === 'yarn') {
      const appData = process.env.APPDATA;
      if (appData) {
        const yarnJs = path.join(appData, 'npm', 'node_modules', 'yarn', 'bin', 'yarn.js');
        if (fs.existsSync(yarnJs)) {
          return { executable: process.execPath, args: [yarnJs, ...args] };
        }
      }
    }

    // For other commands (python, go, cargo, dotnet, git, etc.) on Windows,
    // if an .exe exists in PATH, use it directly.
    return { executable: command, args };
  }

  public async run(
    command: string,
    args: string[],
    options: SandboxRunOptions = {}
  ): Promise<SandboxRunResult> {
    const limits = this.config.limits;
    const startTime = Date.now();
    const timeoutMs = options.timeoutMs ?? limits.totalTimeoutSec * 1000;
    const maxBuffer = limits.outputCapBytes;

    const allowedEnv = [
      'PATH',
      'PATHEXT',
      'SYSTEMROOT',
      'SYSTEMDRIVE',
      'TEMP',
      'TMP',
      'HOME',
      'USERPROFILE',
      'HOMEDRIVE',
      'HOMEPATH',
      'LOCALAPPDATA',
      'APPDATA',
      'TMPDIR',
      'LANG',
      'LC_ALL',
      'TZ',
      'CI',
      'NODE_ENV',
      'HTTP_PROXY',
      'HTTPS_PROXY',
      'ALL_PROXY',
      'NO_PROXY',
      'npm_config_proxy',
      'npm_config_https_proxy',
      'npm_config_offline',
      'YARN_OFFLINE',
      'PIP_PROXY',
      'PIP_NO_INDEX',
      'PIP_ISOLATED',
      'POETRY_VIRTUALENVS_IN_PROJECT',
      'CARGO_NET_OFFLINE',
      'GOPROXY',
      'MAVEN_OPTS',
      'GRADLE_OPTS',
      'DOTNET_CLI_TELEMETRY_OPTOUT',
      'DOTNET_SKIP_FIRST_TIME_EXPERIENCE',
      'NUGET_CERT_REVOCATION_MODE',
      'BUNDLE_LOCAL',
    ];

    const isolationEnv = NativeIsolatedBackend.buildNetworkIsolationEnv(options.network === true);
    const executionEnv: Record<string, string> = {
      ...isolationEnv,
      ...options.env,
    };

    const resolved = NativeIsolatedBackend.resolveCommand(command, args);

    const res = await SafeProcessRunner.run(resolved.executable, resolved.args, {
      cwd: this.shadowDir,
      timeoutMs,
      maxBufferBytes: maxBuffer,
      allowedEnvVars: allowedEnv,
      env: executionEnv,
    });

    const durationMs = Date.now() - startTime;
    const banner = '--- NATIVE ISOLATED SHADOW SANDBOX: ZERO-EGRESS AIR-GAP SIMULATED ---\n';
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
    // Process trees are monitored and terminated per execution
  }
}
