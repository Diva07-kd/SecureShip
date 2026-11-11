import { spawn, execFile, execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { platform } from 'node:os';
import { SecretRedactor } from '@secureship/context-slicer';

export interface ProcessRunOptions {
  cwd?: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
  env?: Record<string, string>;
  allowedEnvVars?: string[];
  signal?: AbortSignal;
  input?: string | Buffer;
}

export interface ProcessRunResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  durationMs: number;
  timedOut: boolean;
  truncated: boolean;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BUFFER_BYTES = 10 * 1024 * 1024; // 10 MB

// Base safe OS environment variables allowlist
const SAFE_OS_ENV_KEYS = new Set([
  'PATH',
  'PATHEXT',
  'SYSTEMROOT',
  'SYSTEMDRIVE',
  'TEMP',
  'TMP',
  'COMSPEC',
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
  'NODE_ENV',
  'VITEST',
  'SECURESHIP_AI_USAGE_PATH',
]);

export class SafeProcessRunner {
  private static readonly isWindows = platform() === 'win32';
  private static userPathWindowsCache: string[] | null = null;

  public static getUserPathWindows(): string[] {
    if (!SafeProcessRunner.isWindows) return [];
    if (SafeProcessRunner.userPathWindowsCache !== null) {
      return SafeProcessRunner.userPathWindowsCache;
    }
    const dirs: string[] = [];
    try {
      const out = execSync('reg query HKCU\\Environment /v Path', {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      const match = out.match(/REG_(?:SZ|EXPAND_SZ)\s+(.*)$/m);
      if (match && match[1]) {
        dirs.push(
          ...match[1]
            .split(';')
            .map((s: string) => s.trim())
            .filter(Boolean)
        );
      }
    } catch {
      // Ignored
    }
    const localAppData = process.env.LOCALAPPDATA;
    if (localAppData) {
      dirs.push(path.join(localAppData, 'Microsoft', 'WinGet', 'Links'));
    }
    SafeProcessRunner.userPathWindowsCache = dirs;
    return dirs;
  }

  /**
   * Sanitizes environment variables according to a strict allowlist.
   */
  public static sanitizeEnvironment(
    customEnv?: Record<string, string>,
    additionalAllowedKeys?: string[]
  ): NodeJS.ProcessEnv {
    const allowed = new Set(SAFE_OS_ENV_KEYS);
    if (additionalAllowedKeys) {
      for (const k of additionalAllowedKeys) {
        allowed.add(k.toUpperCase());
      }
    }

    const cleanEnv: NodeJS.ProcessEnv = {};

    // Only inherit safe OS variables from ambient process.env
    for (const [key, value] of Object.entries(process.env)) {
      if (allowed.has(key.toUpperCase())) {
        // Double check not to pass accidentally matched sensitive keys
        if (!SecretRedactor.isSensitiveKey(key) && value !== undefined) {
          cleanEnv[key] = value;
        }
      }
    }

    if (SafeProcessRunner.isWindows && cleanEnv.PATH) {
      const userDirs = SafeProcessRunner.getUserPathWindows();
      if (userDirs.length > 0) {
        const parts = cleanEnv.PATH.split(';').filter(Boolean);
        cleanEnv.PATH = Array.from(new Set([...parts, ...userDirs])).join(';');
      }
    }

    // Merge explicitly provided custom environment variables
    if (customEnv) {
      for (const [k, v] of Object.entries(customEnv)) {
        if (v !== undefined) {
          cleanEnv[k] = v;
        }
      }
    }

    return cleanEnv;
  }

  /**
   * Safely terminates a child process and all its descendants.
   */
  public static async killProcessTree(pid: number): Promise<void> {
    if (!pid || pid <= 0) return;

    if (SafeProcessRunner.isWindows) {
      await new Promise<void>((resolve) => {
        execFile('taskkill', ['/PID', String(pid), '/T', '/F'], (_err: unknown) => {
          // Ignore error if process already exited
          resolve();
        });
      });
    } else {
      try {
        // Kill process group on POSIX
        process.kill(-pid, 'SIGKILL');
      } catch {
        try {
          process.kill(pid, 'SIGKILL');
        } catch {
          // Already terminated
        }
      }
    }
  }

  /**
   * Executes a command in an isolated, monitored subprocess.
   */
  public static async run(
    executable: string,
    args: string[] = [],
    options: ProcessRunOptions = {}
  ): Promise<ProcessRunResult> {
    if (!executable || typeof executable !== 'string') {
      throw new Error('Executable path must be a non-empty string');
    }

    const cwd = options.cwd ?? process.cwd();
    if (!existsSync(cwd)) {
      throw new Error(`Target working directory does not exist: ${cwd}`);
    }

    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBuffer = options.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES;
    const env = SafeProcessRunner.sanitizeEnvironment(options.env, options.allowedEnvVars);

    const startTime = Date.now();
    let timedOut = false;
    let truncated = false;
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    return new Promise<ProcessRunResult>((resolve, reject) => {
      let child: ReturnType<typeof spawn>;
      let timeoutHandle: NodeJS.Timeout | null = null;
      let isSettled = false;

      try {
        if (
          SafeProcessRunner.isWindows &&
          (executable.toLowerCase().endsWith('.cmd') || executable.toLowerCase().endsWith('.bat'))
        ) {
          throw new Error(
            `Execution of .cmd/.bat files is forbidden under P7 / No Shell policy: ${executable}`
          );
        }

        let execPath = executable;
        let execArgs = args;

        // If executable is a JavaScript/Node script (e.g. .cjs, .js, .mjs),
        // dispatch via the host Node runtime directly (process.execPath).
        // This avoids spawning unsigned ad-hoc temporary executables on Windows,
        // respects P7 / No Shell policy, and guarantees cross-platform reliability.
        if (/\.[cm]?js$/i.test(executable)) {
          execPath = process.execPath;
          execArgs = [executable, ...args];
        }

        child = spawn(execPath, execArgs, {
          cwd,
          env,
          detached: !SafeProcessRunner.isWindows,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch (err) {
        return reject(err);
      }

      const cleanupAndResolve = (exitCode: number | null, signal: NodeJS.Signals | null) => {
        if (isSettled) return;
        isSettled = true;

        if (timeoutHandle) {
          clearTimeout(timeoutHandle);
          timeoutHandle = null;
        }

        const durationMs = Date.now() - startTime;
        const rawStdout = Buffer.concat(stdoutChunks).toString('utf-8');
        const rawStderr = Buffer.concat(stderrChunks).toString('utf-8');

        resolve({
          stdout: rawStdout,
          stderr: rawStderr,
          exitCode,
          signal,
          durationMs,
          timedOut,
          truncated,
        });
      };

      if (timeoutMs > 0) {
        timeoutHandle = setTimeout(async () => {
          timedOut = true;
          if (child.pid) {
            await SafeProcessRunner.killProcessTree(child.pid);
          }
        }, timeoutMs);
      }

      if (options.signal) {
        options.signal.addEventListener('abort', async () => {
          if (child.pid) {
            await SafeProcessRunner.killProcessTree(child.pid);
          }
        });
      }

      if (child.stdout) {
        child.stdout.on('data', (chunk: Buffer) => {
          stdoutBytes += chunk.length;
          if (stdoutBytes <= maxBuffer) {
            stdoutChunks.push(chunk);
          } else {
            truncated = true;
          }
        });
      }

      if (child.stderr) {
        child.stderr.on('data', (chunk: Buffer) => {
          stderrBytes += chunk.length;
          if (stderrBytes <= maxBuffer) {
            stderrChunks.push(chunk);
          } else {
            truncated = true;
          }
        });
      }

      if (options.input && child.stdin) {
        try {
          child.stdin.write(options.input);
          child.stdin.end();
        } catch {
          // Child might have closed stdin early
        }
      }

      child.on('error', (err: Error) => {
        if (isSettled) return;
        isSettled = true;
        if (timeoutHandle) clearTimeout(timeoutHandle);
        reject(err);
      });

      child.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
        cleanupAndResolve(code, signal);
      });
    });
  }
}
