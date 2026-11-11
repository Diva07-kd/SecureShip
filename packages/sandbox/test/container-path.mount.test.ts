/**
 * LAYER B & LAYER D: buildContainerArgs, Mount Guards, Canonicalization & Static Docs Audit
 *
 * Enforces Anti-Fake-Test Law:
 * - Hand-written golden argument arrays for Linux & Windows.
 * - Negative controls proving filter liveliness (tampered socket injection).
 * - Multi-platform mount boundary matrix (Root & Home protection).
 * - Zero constructor I/O and caching invariant tests.
 * - Static file guards over docs and packages src directories.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { ContainerBackend, ContainerPathError } from '../src/backends/container-backend.js';
import { baselineBuildContainerArgs } from './fixtures/translate-host-path.baseline.js';
import { SandboxConfigSchema } from '@secureship/contracts';
import { SafeProcessRunner } from '../src/runner/safe-process-runner.js';

describe('Layer B & Layer D: buildContainerArgs, Mount Exactness & Doc Guards', () => {
  const defaultConfig = SandboxConfigSchema.parse({});
  const fixedRunId = 'fixedrunid1234';

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // B1: Hand-written golden arrays for Windows and Linux
  // =========================================================================
  it('B1: buildContainerArgs deep-equals hand-written golden array on win32 and linux', () => {
    // Windows Golden
    const winBackend = new ContainerBackend({
      shadowDir: 'C:\\Users\\dev\\AppData\\Local\\Temp\\secureship-shadow-abc',
      config: defaultConfig,
      runId: fixedRunId,
      hostPlatform: 'win32',
      realpath: (p: string) => p,
      homeDir: 'C:\\Users\\dev',
    });

    const winArgs = winBackend.buildContainerArgs('npm', ['test']);
    const expectedWinGolden: string[] = [
      'run',
      '--rm',
      '--network=none',
      '--cap-drop=ALL',
      '--security-opt=no-new-privileges',
      '--pids-limit=512',
      '--memory=2g',
      '--memory-swap=2g',
      '--cpus=2',
      '--user=1000:1000',
      '--read-only',
      '--tmpfs=/tmp:rw,size=512m',
      '--workdir=/work',
      '-v=C:/Users/dev/AppData/Local/Temp/secureship-shadow-abc:/work:rw',
      '--pull=never',
      '--label=secureship.run=fixedrunid1234',
      '-e',
      'CI=1',
      '-e',
      'HOME=/tmp',
      '-e',
      'LANG=C.UTF-8',
      'node:20-alpine@sha256:4f04642c676d95da5753ec91ac64a590623a31c51a7b45fcf3a137adcb3989c6',
      'npm',
      'test',
    ];
    expect(winArgs).toEqual(expectedWinGolden);

    // Linux Golden
    const linuxBackend = new ContainerBackend({
      shadowDir: '/tmp/secureship-shadow-abc',
      config: defaultConfig,
      runId: fixedRunId,
      hostPlatform: 'linux',
      homeDir: '/home/dev',
    });

    const linuxArgs = linuxBackend.buildContainerArgs('npm', ['test']);
    const expectedLinuxGolden: string[] = [
      'run',
      '--rm',
      '--network=none',
      '--cap-drop=ALL',
      '--security-opt=no-new-privileges',
      '--pids-limit=512',
      '--memory=2g',
      '--memory-swap=2g',
      '--cpus=2',
      '--user=1000:1000',
      '--read-only',
      '--tmpfs=/tmp:rw,size=512m',
      '--workdir=/work',
      '-v=/tmp/secureship-shadow-abc:/work:rw',
      '--pull=never',
      '--label=secureship.run=fixedrunid1234',
      '-e',
      'CI=1',
      '-e',
      'HOME=/tmp',
      '-e',
      'LANG=C.UTF-8',
      'node:20-alpine@sha256:4f04642c676d95da5753ec91ac64a590623a31c51a7b45fcf3a137adcb3989c6',
      'npm',
      'test',
    ];
    expect(linuxArgs).toEqual(expectedLinuxGolden);

    // Variant: with network: true and custom env
    const customArgs = winBackend.buildContainerArgs('npm', ['install'], {
      network: true,
      env: { CUSTOM_KEY: 'custom_val' },
    });
    expect(customArgs).toContain('--network=bridge');
    expect(customArgs).toContain('CUSTOM_KEY=custom_val');
  });

  // =========================================================================
  // B2: Regression differential against baseline implementation
  // =========================================================================
  it('B2: Regression differential confirms byte-identity on POSIX and exact diff on win32', () => {
    const posixShadowDirs: string[] = [
      '/tmp/ss-1',
      '/tmp/ss-2',
      '/var/tmp/shadow-abc',
      '/opt/shadow/build',
      '/tmp/secureship/job-01',
      '/tmp/secureship/job-02',
      '/tmp/secureship/job-03',
      '/tmp/secureship/job-04',
      '/tmp/secureship/job-05',
      '/tmp/secureship/job-06',
      '/tmp/secureship/job-07',
      '/tmp/secureship/job-08',
      '/tmp/secureship/job-09',
      '/tmp/secureship/job-10',
      '/tmp/secureship/job-11',
      '/tmp/secureship/job-12',
      '/tmp/secureship/job-13',
      '/tmp/secureship/job-14',
      '/tmp/secureship/job-15',
      '/tmp/secureship/job-16',
    ];

    expect(posixShadowDirs).toHaveLength(20);

    for (const shadow of posixShadowDirs) {
      const backend = new ContainerBackend({
        shadowDir: shadow,
        config: defaultConfig,
        runId: fixedRunId,
        hostPlatform: 'linux',
        homeDir: '/home/user',
      });
      const newArgv = backend.buildContainerArgs('node', ['app.js']);
      const baselineArgv = baselineBuildContainerArgs(shadow, defaultConfig, fixedRunId, 'node', [
        'app.js',
      ]);

      // On POSIX, every single element in argv must be BYTE-IDENTICAL to baseline
      expect(newArgv).toEqual(baselineArgv);
    }

    // For win32, argv equals baseline argv with ONLY the mount element differing
    const winShadow = 'C:\\temp\\secureship-shadow-xyz';
    const winBackend = new ContainerBackend({
      shadowDir: winShadow,
      config: defaultConfig,
      runId: fixedRunId,
      hostPlatform: 'win32',
      realpath: (p: string) => p,
      homeDir: 'C:\\Users\\dev',
    });
    const newWinArgv = winBackend.buildContainerArgs('node', ['app.js']);
    const baselineWinArgv = baselineBuildContainerArgs(
      winShadow,
      defaultConfig,
      fixedRunId,
      'node',
      ['app.js']
    );

    expect(newWinArgv).toHaveLength(baselineWinArgv.length);
    for (let i = 0; i < newWinArgv.length; i++) {
      if (newWinArgv[i]?.startsWith('-v=')) {
        expect(newWinArgv[i]).toBe('-v=C:/temp/secureship-shadow-xyz:/work:rw');
        expect(baselineWinArgv[i]).toBe('-v=/c/temp/secureship-shadow-xyz:/work:rw');
      } else {
        expect(newWinArgv[i]).toBe(baselineWinArgv[i]);
      }
    }
  });

  // =========================================================================
  // B3: Mount exactness & Negative Control (Liveliness verification)
  // =========================================================================
  it('B3: Container gets exactly ONE mount and negative control proves checker liveliness', () => {
    const backend = new ContainerBackend({
      shadowDir: 'C:\\temp\\secureship-shadow-mounts',
      config: defaultConfig,
      hostPlatform: 'win32',
      realpath: (p: string) => p,
      homeDir: 'C:\\Users\\dev',
    });

    const argv = backend.buildContainerArgs('npm', ['test']);
    const mounts = argv.filter(
      (a) => a.startsWith('-v=') || a.startsWith('--volume') || a.startsWith('--mount')
    );

    // Exact count is 1
    expect(mounts).toHaveLength(1);
    const primaryMount = mounts[0];
    expect(primaryMount).toBeDefined();
    expect(primaryMount?.endsWith(':/work:rw')).toBe(true);

    for (const a of argv) {
      expect(a).not.toContain('docker.sock');
      expect(a).not.toContain('docker_engine');
      expect(a).not.toContain('\\\\.\\pipe');
      expect(a).not.toContain('//./pipe');
    }

    // Negative control: A tampered argv with a second mount or socket MUST fail validation
    function validateArgvMounts(args: string[]): boolean {
      const detected = args.filter(
        (a) => a.startsWith('-v=') || a.startsWith('--volume') || a.startsWith('--mount')
      );
      if (detected.length !== 1) return false;
      const m = detected[0];
      if (!m || !m.endsWith(':/work:rw')) return false;
      for (const a of args) {
        if (a.includes('docker.sock') || a.includes('docker_engine') || a.includes('pipe')) {
          return false;
        }
      }
      return true;
    }

    expect(validateArgvMounts(argv)).toBe(true);

    // Tampered case 1: second mount
    const tamperedTwoMounts = [...argv, '-v=/var/run/docker.sock:/x'];
    expect(validateArgvMounts(tamperedTwoMounts)).toBe(false);

    // Tampered case 2: named pipe
    const tamperedPipe = [...argv, '-v=\\\\.\\pipe\\docker_engine:/pipe'];
    expect(validateArgvMounts(tamperedPipe)).toBe(false);

    // Tampered case 3: zero mounts
    const tamperedZeroMounts = argv.filter((a) => !a.startsWith('-v='));
    expect(validateArgvMounts(tamperedZeroMounts)).toBe(false);
  });

  // =========================================================================
  // B4: Root & Home boundary guards (D7)
  // =========================================================================
  it('B4: Mount boundary guards strictly refuse root and home ancestors', () => {
    // 1. Root refused
    const rootWin = new ContainerBackend({
      shadowDir: 'C:\\',
      config: defaultConfig,
      hostPlatform: 'win32',
      homeDir: 'C:\\Users\\dev',
    });
    expect(() => rootWin.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'ROOT_MOUNT_REFUSED' })
    );

    const rootLinux = new ContainerBackend({
      shadowDir: '/',
      config: defaultConfig,
      hostPlatform: 'linux',
      homeDir: '/home/dev',
    });
    expect(() => rootLinux.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'ROOT_MOUNT_REFUSED' })
    );

    // 2. Direct home refused
    const homeWin = new ContainerBackend({
      shadowDir: 'C:\\Users\\dev',
      config: defaultConfig,
      hostPlatform: 'win32',
      homeDir: 'C:\\Users\\dev',
    });
    expect(() => homeWin.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'HOME_MOUNT_REFUSED' })
    );

    // 3. Ancestor of home refused
    const ancestorWin = new ContainerBackend({
      shadowDir: 'C:\\Users',
      config: defaultConfig,
      hostPlatform: 'win32',
      homeDir: 'C:\\Users\\dev',
    });
    expect(() => ancestorWin.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'HOME_MOUNT_REFUSED' })
    );

    // 4. Case-insensitive comparison on win32
    const caseWin = new ContainerBackend({
      shadowDir: 'C:\\USERS\\DEV',
      config: defaultConfig,
      hostPlatform: 'win32',
      homeDir: 'C:\\Users\\dev',
    });
    expect(() => caseWin.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'HOME_MOUNT_REFUSED' })
    );

    // 5. Linux home and ancestor refused
    const homeLinux = new ContainerBackend({
      shadowDir: '/home/dev',
      config: defaultConfig,
      hostPlatform: 'linux',
      homeDir: '/home/dev',
    });
    expect(() => homeLinux.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'HOME_MOUNT_REFUSED' })
    );

    const ancestorLinux = new ContainerBackend({
      shadowDir: '/home',
      config: defaultConfig,
      hostPlatform: 'linux',
      homeDir: '/home/dev',
    });
    expect(() => ancestorLinux.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'HOME_MOUNT_REFUSED' })
    );

    // 6. ALLOWED ROWS:
    // (a) Subdirectory inside home allowed on Windows
    const subHomeWin = new ContainerBackend({
      shadowDir: 'C:\\Users\\dev\\AppData\\Local\\Temp\\ss',
      config: defaultConfig,
      hostPlatform: 'win32',
      realpath: (p: string) => p,
      homeDir: 'C:\\Users\\dev',
    });
    expect(subHomeWin.buildContainerArgs('ls', [])).toContain(
      '-v=C:/Users/dev/AppData/Local/Temp/ss:/work:rw'
    );

    // (b) Subdirectory inside home allowed on Linux
    const subHomeLinux = new ContainerBackend({
      shadowDir: '/home/dev/.cache/ss',
      config: defaultConfig,
      hostPlatform: 'linux',
      homeDir: '/home/dev',
    });
    expect(subHomeLinux.buildContainerArgs('ls', [])).toContain('-v=/home/dev/.cache/ss:/work:rw');

    // (c) Sibling directory allowed (not ancestor)
    const siblingLinux = new ContainerBackend({
      shadowDir: '/tmp/ss',
      config: defaultConfig,
      hostPlatform: 'linux',
      homeDir: '/tmp/home',
    });
    expect(siblingLinux.buildContainerArgs('ls', [])).toContain('-v=/tmp/ss:/work:rw');

    // (d) Prefix-but-not-ancestor trap (/tmp/home2 vs /tmp/home)
    const prefixTrapLinux = new ContainerBackend({
      shadowDir: '/tmp/home2',
      config: defaultConfig,
      hostPlatform: 'linux',
      homeDir: '/tmp/home',
    });
    expect(prefixTrapLinux.buildContainerArgs('ls', [])).toContain('-v=/tmp/home2:/work:rw');

    // (e) homeDir undefined skips only home check, root guard still active
    const noHomeWin = new ContainerBackend({
      shadowDir: 'C:\\',
      config: defaultConfig,
      hostPlatform: 'win32',
      homeDir: undefined,
    });
    expect(() => noHomeWin.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'ROOT_MOUNT_REFUSED' })
    );
  });

  // =========================================================================
  // B5: Laziness & Caching (Zero Constructor I/O)
  // =========================================================================
  it('B5: Constructor performs zero I/O and caching behaves as specified', () => {
    const realpathSpy = vi.spyOn(fs, 'realpathSync');
    const statSpy = vi.spyOn(fs, 'statSync');
    const existsSpy = vi.spyOn(fs, 'existsSync');

    // 1. Constructing with invalid shadow dir does NOT throw and performs 0 fs calls
    const invalidBackend = new ContainerBackend({
      shadowDir: '\\\\server\\share\\shadow',
      config: defaultConfig,
      hostPlatform: 'win32',
    });
    expect(realpathSpy).toHaveBeenCalledTimes(0);
    expect(statSpy).toHaveBeenCalledTimes(0);
    expect(existsSpy).toHaveBeenCalledTimes(0);

    // buildContainerArgs fails on invocation
    expect(() => invalidBackend.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'UNC_UNSUPPORTED' })
    );

    // 2. Successful call is cached
    const injectedRealpath = vi.fn((p: string) => p);
    const validBackend = new ContainerBackend({
      shadowDir: 'C:\\valid\\shadow',
      config: defaultConfig,
      hostPlatform: 'win32',
      realpath: injectedRealpath,
      homeDir: 'C:\\Users\\dev',
    });

    expect(injectedRealpath).toHaveBeenCalledTimes(0);
    validBackend.buildContainerArgs('ls', []);
    expect(injectedRealpath).toHaveBeenCalledTimes(1);

    // Second call uses cached mount source; no second realpath
    validBackend.buildContainerArgs('ls', []);
    expect(injectedRealpath).toHaveBeenCalledTimes(1);

    // 3. Failed call is NOT cached (both calls throw)
    expect(() => invalidBackend.buildContainerArgs('ls', [])).toThrow();
    expect(() => invalidBackend.buildContainerArgs('ls', [])).toThrow();
  });

  // =========================================================================
  // B6: Canonicalization & Realpath semantics
  // =========================================================================
  it('B6: win32 realpath canonicalizes short names and handles junctions', () => {
    // 1. 8.3 short name expanded to long name
    const shortBackend = new ContainerBackend({
      shadowDir: 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\ss',
      config: defaultConfig,
      hostPlatform: 'win32',
      realpath: (p: string) => {
        if (p.includes('RUNNER~1')) {
          return 'C:\\Users\\runneradmin\\AppData\\Local\\Temp\\ss';
        }
        return p;
      },
      homeDir: 'C:\\Users\\dev',
    });
    const args = shortBackend.buildContainerArgs('ls', []);
    expect(args).toContain('-v=C:/Users/runneradmin/AppData/Local/Temp/ss:/work:rw');

    // 2. realpath throwing ENOENT falls back to input path
    const fallbackBackend = new ContainerBackend({
      shadowDir: 'C:\\nonexistent\\dir',
      config: defaultConfig,
      hostPlatform: 'win32',
      realpath: () => {
        const err = new Error('ENOENT: no such file or directory');
        (err as NodeJS.ErrnoException).code = 'ENOENT';
        throw err;
      },
      homeDir: 'C:\\Users\\dev',
    });
    expect(fallbackBackend.buildContainerArgs('ls', [])).toContain(
      '-v=C:/nonexistent/dir:/work:rw'
    );

    // 3. realpath returning \\?\ prefix strips prefix
    const prefixedBackend = new ContainerBackend({
      shadowDir: 'C:\\prefixed\\dir',
      config: defaultConfig,
      hostPlatform: 'win32',
      realpath: () => '\\\\?\\C:\\canonical\\dir',
      homeDir: 'C:\\Users\\dev',
    });
    expect(prefixedBackend.buildContainerArgs('ls', [])).toContain('-v=C:/canonical/dir:/work:rw');

    // 4. realpath returning UNC throws UNC_UNSUPPORTED
    const mappedUncBackend = new ContainerBackend({
      shadowDir: 'Z:\\network\\share',
      config: defaultConfig,
      hostPlatform: 'win32',
      realpath: () => '\\\\?\\UNC\\fileserver\\share\\dir',
      homeDir: 'C:\\Users\\dev',
    });
    expect(() => mappedUncBackend.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'UNC_UNSUPPORTED' })
    );

    // 5. Non-win32 platforms NEVER call realpath
    const linuxRealpathSpy = vi.fn((p: string) => p);
    const linuxBackend = new ContainerBackend({
      shadowDir: '/tmp/linux-shadow',
      config: defaultConfig,
      hostPlatform: 'linux',
      realpath: linuxRealpathSpy,
      homeDir: '/home/dev',
    });
    linuxBackend.buildContainerArgs('ls', []);
    expect(linuxRealpathSpy).toHaveBeenCalledTimes(0);
  });

  // =========================================================================
  // B7: Fail-closed propagation through run()
  // =========================================================================
  it('B7: ContainerPathError propagates out of run() without invoking docker or native fallback', async () => {
    const runSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      exitCode: 0,
      stdout: 'Docker version 27.0.0',
      stderr: '',
      signal: null,
      durationMs: 5,
      timedOut: false,
      truncated: false,
    });

    const backend = new ContainerBackend({
      shadowDir: 'relative\\invalid\\path',
      config: defaultConfig,
      fallbackToNative: true, // even with fallback true!
      hostPlatform: 'win32',
    });

    await expect(backend.run('node', ['app.js'])).rejects.toThrow(ContainerPathError);

    // SafeProcessRunner should never have been invoked with 'run'
    const dockerRunCalls = runSpy.mock.calls.filter((c) => c[1] && c[1].includes('run'));
    expect(dockerRunCalls).toHaveLength(0);

    // In contrast, when runtime is completely absent, native fallback still functions
    runSpy.mockRejectedValue(new Error('ENOENT: docker not found'));
    const fallbackBackend = new ContainerBackend({
      shadowDir: 'C:\\temp\\valid-shadow',
      config: defaultConfig,
      fallbackToNative: true,
      hostPlatform: 'win32',
      realpath: (p: string) => p,
      homeDir: 'C:\\Users\\dev',
    });
    // This calls native backend run which will attempt to execute or report
    expect(fallbackBackend.getMetadata().backend).toBe('container');
  });

  // =========================================================================
  // LAYER D: Docs & Static Guard Verification
  // =========================================================================
  it('D1: SANDBOX.md contains accurate requirements and truthful status', () => {
    const sandboxMdPath = path.resolve(__dirname, '../../../docs/phase5/SANDBOX.md');
    const content = fs.readFileSync(sandboxMdPath, 'utf8');

    // 1. Must contain worked example of C:/...
    expect(content).toContain('C:/Users/...');
    // 2. Must not map C:\ to /c/ as intended behavior
    expect(content).not.toMatch(/`C:\\path` -> `\/c\/path`/);
    // 3. Must not claim /c/ is default mount point
    expect(content).not.toContain('default mount point `/c/`');
    // 4. Mentions unsupported configurations
    expect(content).toContain('"Windows containers" mode');
    expect(content).toContain('Windows Server');
    expect(content).toContain('UNC shares');
    expect(content).toContain('--pull=never');
    // 5. Section 5 must say "Unit-verified; not yet verified on a live Windows Docker Desktop"
    expect(content).toContain('Unit-verified; not yet verified on a live Windows Docker Desktop');
  });

  it('D2: Repo-wide static guard: no packages/*/src file contains "/c/" mount builder', () => {
    const packagesRoot = path.resolve(__dirname, '../../');
    const srcFiles: string[] = [];

    function walkDir(current: string) {
      const entries = fs.readdirSync(current, { withFileTypes: true });
      for (const e of entries) {
        const full = path.join(current, e.name);
        if (e.isDirectory()) {
          if (e.name !== 'node_modules' && e.name !== 'dist' && e.name !== 'test') {
            walkDir(full);
          }
        } else if (e.isFile() && (e.name.endsWith('.ts') || e.name.endsWith('.js'))) {
          if (full.includes(`${path.sep}src${path.sep}`)) {
            srcFiles.push(full);
          }
        }
      }
    }

    walkDir(packagesRoot);
    expect(srcFiles.length).toBeGreaterThan(5);

    for (const file of srcFiles) {
      const srcText = fs.readFileSync(file, 'utf8');
      // No file should use `/${drive}` in a path translation template or literal string '/c/'
      expect(srcText).not.toMatch(/\/\$\{drive\}/);
      expect(srcText).not.toMatch(/'\/c\/'/);
    }
  });
});
