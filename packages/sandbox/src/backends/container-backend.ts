import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { SandboxConfig } from '@secureship/contracts';
import { SafeProcessRunner } from '../runner/safe-process-runner.js';
import { SecretRedactor } from '@secureship/context-slicer';
import {
  type ISandboxBackend,
  type SandboxRunOptions,
  type SandboxRunResult,
} from './sandbox-backend.interface.js';
import { NativeIsolatedBackend } from './native-isolated-backend.js';

export type ContainerPathErrorCode =
  | 'EMPTY'
  | 'ILLEGAL_CHARS'
  | 'UNC_UNSUPPORTED'
  | 'DEVICE_PATH_UNSUPPORTED'
  | 'DRIVE_RELATIVE'
  | 'POSIX_STYLE_ON_WINDOWS'
  | 'NOT_ABSOLUTE'
  | 'COLON_IN_PATH'
  | 'ROOT_MOUNT_REFUSED'
  | 'HOME_MOUNT_REFUSED';

export class ContainerPathError extends Error {
  public readonly code: ContainerPathErrorCode;

  constructor(code: ContainerPathErrorCode, message: string) {
    super(message);
    this.name = 'ContainerPathError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface ContainerBackendOptions {
  shadowDir: string;
  config: SandboxConfig;
  runId?: string;
  fallbackToNative?: boolean;
  hostPlatform?: NodeJS.Platform;
  realpath?: (p: string) => string;
  homeDir?: string;
}

export class ContainerBackend implements ISandboxBackend {
  public readonly name = 'container';
  private readonly shadowDir: string;
  private readonly config: SandboxConfig;
  private readonly runId: string;
  private readonly fallbackToNative: boolean;
  private readonly hostPlatform: NodeJS.Platform;
  private readonly realpathFn: (p: string) => string;
  private readonly homeDir?: string;
  private cachedMountSource: string | null = null;
  private resolvedRuntime: 'docker' | 'podman' | null = null;
  private runtimeVersion: string | null = null;
  private imageDigest: string | null = null;
  private daemonActiveCache: boolean | null = null;
  private nativeFallbackBackend: NativeIsolatedBackend | null = null;

  constructor(options: ContainerBackendOptions) {
    this.shadowDir = options.shadowDir;
    this.config = options.config;
    this.runId = options.runId ?? crypto.randomBytes(8).toString('hex');
    this.fallbackToNative = options.fallbackToNative ?? false;
    this.hostPlatform = options.hostPlatform ?? process.platform;
    this.realpathFn = options.realpath ?? fs.realpathSync.native;
    this.homeDir = options.homeDir;
  }

  /**
   * Translates a host directory path to container volume mount source format.
   *
   * ## Docker Windows Volume Rule:
   * Under Docker Desktop on Windows (moby volume/mounts/windows_parser.go), volume specifications
   * (-v <source>:<destination>:<mode>) require host bind sources to be absolute drive paths
   * starting with a drive letter and colon (e.g. `C:/...` or `C:\...`). If the source does not start
   * with a drive letter, the Windows volume parser treats the source as a NAMED VOLUME candidate
   * rather than a host path.
   *
   * ## The `/c/...` Translation Defect:
   * The historical translation `C:\Users\... -> /c/Users/...` was specific to legacy Docker Toolbox
   * / MSYS environments. On modern Docker Desktop for Windows, passing `-v=/c/Users/...:/work:rw`
   * causes the volume parser to interpret `/c/Users/...` as a named volume. Because volume names
   * cannot contain slashes, the daemon rejects it with:
   * `docker: Error response from daemon: create \c\Users\...: includes invalid characters for a local volume name`
   * Furthermore, WSL2's automount location (`/mnt/c`) is internal to the Linux subsystem and
   * unrelated to Docker Windows CLI host bind syntax, which expects `C:/...`.
   *
   * ## Accepted Shapes (win32):
   * - Absolute drive paths: `C:\Users\dev\project`, `d:\data\app`, `C:/Users/dev/project`
   * - Paths with spaces: `C:\Program Files\Project`
   * - Extended-length drive paths: `\\?\C:\Users\dev\project` (`\\?\` prefix is stripped)
   * Drive letter case is preserved; backslashes are converted to forward slashes; trailing slashes
   * are trimmed unless the path is a root drive (`X:/`).
   *
   * ## Rejected Shapes (Fail-Closed on win32):
   * - Empty or non-string paths (throws `ContainerPathError` with code `EMPTY`)
   * - Control characters below 0x20 or any of `" < > | * ?` (code `ILLEGAL_CHARS`)
   * - UNC paths: `\\server\share`, `//server/share`, `\\?\UNC\...` (code `UNC_UNSUPPORTED`)
   * - Device or named pipe paths: `\\.\pipe\...`, `//./pipe/...` (code `DEVICE_PATH_UNSUPPORTED`)
   * - Drive-relative paths: `C:foo`, `C:` (code `DRIVE_RELATIVE`)
   * - POSIX-style paths on Windows: `/c/Users/...`, `\Users\...` (code `POSIX_STYLE_ON_WINDOWS`)
   * - Relative paths: `foo\bar`, `.` (code `NOT_ABSOLUTE`)
   * - Colons after drive letter: `C:\path:foo` (code `COLON_IN_PATH`)
   *
   * ## Non-Windows Platforms (POSIX):
   * Paths must be absolute (`path.posix.isAbsolute`), contain no control characters or colons (`:`),
   * and are returned BYTE-IDENTICAL without normalization or conversion.
   *
   * @param hostPath - The raw host directory path to translate.
   * @param platform - Injected platform semantics (defaults to process.platform).
   * @returns Canonical container mount source string formatted as `X:/...` (win32) or original POSIX path.
   * @throws {ContainerPathError} Fail-closed on any invalid, relative, ambiguous, or forbidden shape.
   */
  public static translateHostPath(
    hostPath: string,
    platform: NodeJS.Platform = process.platform
  ): string {
    if (platform === 'win32') {
      // D2: win32 algorithm, in exactly this order:
      // a. Empty or non-string: EMPTY
      if (typeof hostPath !== 'string' || hostPath.length === 0) {
        throw new ContainerPathError('EMPTY', 'Host path cannot be empty.');
      }

      // b. Strip a leading \\?\ or //?/ prefix. If followed by UNC\ or UNC/: UNC_UNSUPPORTED.
      // Leading \\.\ or //./ (device/pipe): DEVICE_PATH_UNSUPPORTED.
      let stripped = hostPath;
      if (hostPath.startsWith('\\\\.\\') || hostPath.startsWith('//./')) {
        throw new ContainerPathError(
          'DEVICE_PATH_UNSUPPORTED',
          `Device or named pipe paths are unsupported for container mounts: '${hostPath}'.`
        );
      }
      if (hostPath.startsWith('\\\\?\\') || hostPath.startsWith('//?/')) {
        stripped = hostPath.slice(4);
        if (/^unc[\\/]/i.test(stripped)) {
          throw new ContainerPathError(
            'UNC_UNSUPPORTED',
            `UNC paths are unsupported for container mounts ('${hostPath}'): set TEMP/TMP (Windows) or TMPDIR (POSIX) to a local directory.`
          );
        }
      }

      // a. (cont.) Any char below 0x20, or any of " < > | * ? (checked AFTER stripping \\?\ in step b): ILLEGAL_CHARS
      for (let i = 0; i < stripped.length; i++) {
        const code = stripped.charCodeAt(i);
        if (
          code < 0x20 ||
          code === 0x22 || // "
          code === 0x3c || // <
          code === 0x3e || // >
          code === 0x7c || // |
          code === 0x2a || // *
          code === 0x3f // ?
        ) {
          throw new ContainerPathError(
            'ILLEGAL_CHARS',
            `Host path contains illegal characters: '${hostPath}'.`
          );
        }
      }

      // c. Two leading separators (any mix of / and \): UNC_UNSUPPORTED.
      if (/^[\\/]{2}/.test(stripped)) {
        throw new ContainerPathError(
          'UNC_UNSUPPORTED',
          `UNC paths are unsupported for container mounts ('${hostPath}'): set TEMP/TMP (Windows) or TMPDIR (POSIX) to a local directory.`
        );
      }

      // d. A drive letter + colon not followed by / or \ (including bare C:): DRIVE_RELATIVE.
      if (/^[A-Za-z]:(?![\\/])/.test(stripped)) {
        throw new ContainerPathError(
          'DRIVE_RELATIVE',
          `Drive-relative paths like '${hostPath}' are ambiguous and unsupported. Use an absolute path (e.g. C:/...).`
        );
      }

      // e. A single leading separator with no drive (covers /c/Users/x and \Users\x): POSIX_STYLE_ON_WINDOWS.
      if (/^[\\/]/.test(stripped)) {
        throw new ContainerPathError(
          'POSIX_STYLE_ON_WINDOWS',
          `Invalid Windows container mount path '${hostPath}': POSIX-style paths are not accepted by Docker on Windows. Docker requires absolute drive paths formatted as 'C:/...'.`
        );
      }

      // f. Not matching ^[A-Za-z]:[\\/]: NOT_ABSOLUTE. Relative paths are rejected.
      if (!/^[A-Za-z]:[\\/]/.test(stripped)) {
        throw new ContainerPathError(
          'NOT_ABSOLUTE',
          `Relative path '${hostPath}' is not supported for container mounts. Host path must be an absolute drive path (e.g. C:/...).`
        );
      }

      // g. Normalize with path.win32.normalize, replace every backslash with /, and remove trailing / unless exactly X:/
      let normalized = path.win32.normalize(stripped).replace(/\\/g, '/');
      while (normalized.length > 3 && normalized.endsWith('/')) {
        normalized = normalized.slice(0, -1);
      }

      // h. Any : after index 1: COLON_IN_PATH.
      if (normalized.indexOf(':', 2) !== -1) {
        throw new ContainerPathError(
          'COLON_IN_PATH',
          `Host path cannot contain ':' after the drive letter as Docker volume syntax uses ':' as separator: '${hostPath}'.`
        );
      }

      return normalized;
    } else {
      // D3: Non-win32 algorithm:
      // EMPTY
      if (typeof hostPath !== 'string' || hostPath.length === 0) {
        throw new ContainerPathError('EMPTY', 'Host path cannot be empty.');
      }
      // Control chars (below 0x20, including NUL): ILLEGAL_CHARS
      for (let i = 0; i < hostPath.length; i++) {
        if (hostPath.charCodeAt(i) < 0x20) {
          throw new ContainerPathError(
            'ILLEGAL_CHARS',
            `Host path contains illegal control characters: '${hostPath}'.`
          );
        }
      }
      // Not path.posix.isAbsolute: NOT_ABSOLUTE
      if (!path.posix.isAbsolute(hostPath)) {
        throw new ContainerPathError(
          'NOT_ABSOLUTE',
          `Host path must be an absolute POSIX path starting with '/': '${hostPath}'.`
        );
      }
      // Contains :: COLON_IN_PATH
      if (hostPath.includes(':')) {
        throw new ContainerPathError(
          'COLON_IN_PATH',
          `Host path cannot contain ':' as Docker volume syntax uses ':' as separator: '${hostPath}'.`
        );
      }
      // Otherwise return input unchanged (BYTE-IDENTICAL per I2)
      return hostPath;
    }
  }

  private getMountSource(): string {
    if (this.cachedMountSource !== null) {
      return this.cachedMountSource;
    }

    let candidatePath = this.shadowDir;

    // D6. win32 canonicalization (defense in depth)
    if (this.hostPlatform === 'win32') {
      // Only call realpath on paths that are absolute drive paths, UNC, or extended/device paths.
      // Calling realpath on relative paths (e.g. 'packages', '.') would resolve them against process.cwd(),
      // violating D2 f ("Relative paths are rejected, never resolved against the cwd").
      const isPotentiallyAbsolute =
        /^[A-Za-z]:[\\/]/.test(this.shadowDir) || /^[\\/]{2}/.test(this.shadowDir);

      if (isPotentiallyAbsolute) {
        try {
          candidatePath = this.realpathFn(this.shadowDir);
        } catch {
          candidatePath = this.shadowDir;
        }

        // If candidatePath has \\?\ or //?/ prefix:
        if (candidatePath.startsWith('\\\\?\\') || candidatePath.startsWith('//?/')) {
          const rest = candidatePath.slice(4);
          if (/^unc[\\/]/i.test(rest)) {
            throw new ContainerPathError(
              'UNC_UNSUPPORTED',
              `UNC paths are unsupported for container mounts ('${candidatePath}'): set TEMP/TMP (Windows) or TMPDIR (POSIX) to a local directory.`
            );
          }
          // Strip the \\?\ or //?/ prefix (keep the drive path)
          candidatePath = rest;
        } else if (/^[\\/]{2}/.test(candidatePath)) {
          // Standard UNC network path (\\server\share or //server/share)
          throw new ContainerPathError(
            'UNC_UNSUPPORTED',
            `UNC paths are unsupported for container mounts ('${candidatePath}'): set TEMP/TMP (Windows) or TMPDIR (POSIX) to a local directory.`
          );
        }
      }
    }

    const translatedSource = ContainerBackend.translateHostPath(candidatePath, this.hostPlatform);

    // D7. Mount-root guard
    if (this.hostPlatform === 'win32') {
      if (/^[A-Za-z]:\/$/.test(translatedSource)) {
        throw new ContainerPathError(
          'ROOT_MOUNT_REFUSED',
          `Refusing to mount root directory '${translatedSource}' as container volume.`
        );
      }
    } else {
      if (translatedSource === '/') {
        throw new ContainerPathError(
          'ROOT_MOUNT_REFUSED',
          `Refusing to mount root directory '/' as container volume.`
        );
      }
    }

    // D7. Home directory guard (resolve homeDir lazily)
    let effectiveHome = this.homeDir;
    if (effectiveHome === undefined) {
      try {
        effectiveHome = os.homedir();
      } catch {
        effectiveHome = undefined;
      }
    }

    if (effectiveHome) {
      try {
        const translatedHome = ContainerBackend.translateHostPath(effectiveHome, this.hostPlatform);

        if (this.hostPlatform === 'win32') {
          const sourceLower = translatedSource.toLowerCase();
          const homeLower = translatedHome.toLowerCase();

          const sourceDrive = sourceLower.slice(0, 2);
          const homeDrive = homeLower.slice(0, 2);

          if (sourceDrive === homeDrive) {
            const sourceSegments = sourceLower.split('/').filter(Boolean);
            const homeSegments = homeLower.split('/').filter(Boolean);

            if (sourceSegments.length <= homeSegments.length) {
              const isAncestorOrEqual = sourceSegments.every(
                (seg, idx) => seg === homeSegments[idx]
              );
              if (isAncestorOrEqual) {
                throw new ContainerPathError(
                  'HOME_MOUNT_REFUSED',
                  `Refusing to mount user home directory or ancestor '${translatedSource}' (home: '${translatedHome}').`
                );
              }
            }
          }
        } else {
          if (translatedSource === translatedHome) {
            throw new ContainerPathError(
              'HOME_MOUNT_REFUSED',
              `Refusing to mount user home directory '${translatedSource}'.`
            );
          }
          const rel = path.posix.relative(translatedSource, translatedHome);
          if (rel === '' || (!rel.startsWith('..') && !path.posix.isAbsolute(rel))) {
            throw new ContainerPathError(
              'HOME_MOUNT_REFUSED',
              `Refusing to mount user home directory or ancestor '${translatedSource}' (home: '${translatedHome}').`
            );
          }
        }
      } catch (err) {
        if (err instanceof ContainerPathError && err.code === 'HOME_MOUNT_REFUSED') {
          throw err;
        }
        // If homeDir cannot be determined, skip only the home check per D7
      }
    }

    this.cachedMountSource = translatedSource;
    return translatedSource;
  }

  public async isAvailable(): Promise<boolean> {
    const runtime = await this.detectRuntime();
    return runtime !== null;
  }

  public async detectRuntime(): Promise<'docker' | 'podman' | null> {
    if (this.resolvedRuntime) return this.resolvedRuntime;

    const preference = this.config.runtime;
    const candidates =
      preference === 'auto'
        ? ['docker', 'podman']
        : preference === 'docker'
          ? ['docker']
          : ['podman'];

    for (const bin of candidates) {
      try {
        const res = await SafeProcessRunner.run(bin, ['--version'], { timeoutMs: 5000 });
        if (res.exitCode === 0) {
          this.resolvedRuntime = bin as 'docker' | 'podman';
          this.runtimeVersion = res.stdout.trim();
          return this.resolvedRuntime;
        }
      } catch {
        // Continue
      }
    }

    return null;
  }

  public async isDaemonActive(): Promise<boolean> {
    if (this.daemonActiveCache !== null) {
      return this.daemonActiveCache;
    }

    const runtime = await this.detectRuntime();
    if (!runtime) {
      this.daemonActiveCache = false;
      return false;
    }

    try {
      const res = await SafeProcessRunner.run(runtime, ['info'], { timeoutMs: 2000 });
      this.daemonActiveCache = res.exitCode === 0;
      return this.daemonActiveCache;
    } catch {
      this.daemonActiveCache = false;
      return false;
    }
  }

  public getMetadata(): {
    backend: 'container' | 'native-isolated';
    runtime?: string;
    runtimeVersion?: string;
    imageDigest?: string;
  } {
    if (this.nativeFallbackBackend) {
      return {
        backend: 'native-isolated',
      };
    }
    return {
      backend: 'container',
      runtime: this.resolvedRuntime ?? undefined,
      runtimeVersion: this.runtimeVersion ?? undefined,
      imageDigest: this.imageDigest ?? undefined,
    };
  }

  public buildContainerArgs(
    command: string,
    args: string[],
    options: SandboxRunOptions = {}
  ): string[] {
    const limits = this.config.limits;
    const networkMode = options.network ? 'bridge' : 'none';
    const translatedShadow = this.getMountSource();

    const image =
      this.config.images.node ||
      this.config.images.python ||
      'node:20-alpine@sha256:4f04642c676d95da5753ec91ac64a590623a31c51a7b45fcf3a137adcb3989c6';
    this.imageDigest = image;

    const containerArgs: string[] = [
      'run',
      '--rm',
      `--network=${networkMode}`,
      '--cap-drop=ALL',
      '--security-opt=no-new-privileges',
      `--pids-limit=${limits.pids}`,
      `--memory=${limits.memory}`,
      `--memory-swap=${limits.memory}`,
      `--cpus=${limits.cpus}`,
      '--user=1000:1000',
      '--read-only',
      `--tmpfs=/tmp:rw,size=${limits.tmpfsMb}m`,
      '--workdir=/work',
      `-v=${translatedShadow}:/work:rw`,
      '--pull=never',
      `--label=secureship.run=${this.runId}`,
      '-e',
      'CI=1',
      '-e',
      'HOME=/tmp',
      '-e',
      'LANG=C.UTF-8',
    ];

    if (options.env) {
      for (const [k, v] of Object.entries(options.env)) {
        containerArgs.push('-e', `${k}=${v}`);
      }
    }

    containerArgs.push(image, command, ...args);
    return containerArgs;
  }

  public async run(
    command: string,
    args: string[],
    options: SandboxRunOptions = {}
  ): Promise<SandboxRunResult> {
    const runtime = await this.detectRuntime();

    if (!runtime) {
      if (this.fallbackToNative) {
        if (!this.nativeFallbackBackend) {
          this.nativeFallbackBackend = new NativeIsolatedBackend({
            shadowDir: this.shadowDir,
            config: this.config,
          });
        }
        return this.nativeFallbackBackend.run(command, args, options);
      }

      throw new Error(
        `Sandbox Infrastructure Failure: No container runtime (docker/podman) is available on PATH.`
      );
    }

    if (this.fallbackToNative) {
      const daemonActive = await this.isDaemonActive();
      if (!daemonActive) {
        if (!this.nativeFallbackBackend) {
          this.nativeFallbackBackend = new NativeIsolatedBackend({
            shadowDir: this.shadowDir,
            config: this.config,
          });
        }
        return this.nativeFallbackBackend.run(command, args, options);
      }
    }

    const limits = this.config.limits;
    const containerArgs = this.buildContainerArgs(command, args, options);

    const startTime = Date.now();
    const timeoutMs = options.timeoutMs ?? limits.totalTimeoutSec * 1000;
    const maxBuffer = limits.outputCapBytes;

    const res = await SafeProcessRunner.run(runtime, containerArgs, {
      timeoutMs,
      maxBufferBytes: maxBuffer,
    });

    const durationMs = Date.now() - startTime;
    const combinedOutput = (res.stdout + '\n' + res.stderr).slice(-maxBuffer);
    const redactedOutput = SecretRedactor.redactText(combinedOutput);
    const outputSha256 = crypto.createHash('sha256').update(combinedOutput).digest('hex');
    const outputTail = redactedOutput.slice(-2048);

    return {
      exitCode: res.exitCode,
      timedOut: res.timedOut,
      durationMs,
      stdout: res.stdout,
      stderr: res.stderr,
      outputSha256,
      outputTail,
      command,
      argv: args,
    };
  }

  public async cleanup(): Promise<void> {
    if (this.nativeFallbackBackend) {
      await this.nativeFallbackBackend.cleanup();
    }

    const runtime = this.resolvedRuntime;
    if (!runtime) return;

    try {
      // Remove any container associated with this run ID
      await SafeProcessRunner.run(
        runtime,
        ['rm', '-f', '--filter', `label=secureship.run=${this.runId}`],
        { timeoutMs: 5000 }
      );
    } catch {
      // Ignore cleanup error
    }
  }
}
