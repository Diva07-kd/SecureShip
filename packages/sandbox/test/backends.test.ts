import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ContainerBackend, ContainerPathError } from '../src/backends/container-backend.js';
import { HostBackend } from '../src/backends/host-backend.js';
import { FakeSandboxBackend } from '../src/backends/fake-backend.js';
import { SafeProcessRunner } from '../src/runner/safe-process-runner.js';
import { SandboxConfigSchema } from '@secureship/contracts';

describe('Sandbox Backends Suite (Container, Host, Fake)', () => {
  let tempDir: string;
  const defaultConfig = SandboxConfigSchema.parse({});

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-backend-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('ContainerBackend translates Windows host paths to container format', () => {
    const cases: Array<{
      input: string;
      platform: NodeJS.Platform;
      expected: string;
    }> = [
      {
        input: 'C:\\Users\\dev\\project',
        platform: 'win32',
        expected: 'C:/Users/dev/project',
      },
      {
        input: 'd:\\data\\app',
        platform: 'win32',
        expected: 'd:/data/app',
      },
      {
        input: 'C:\\Program Files\\Project',
        platform: 'win32',
        expected: 'C:/Program Files/Project',
      },
      {
        input: 'D:/data/app',
        platform: 'win32',
        expected: 'D:/data/app',
      },
      {
        input: '/home/user/project',
        platform: 'linux',
        expected: '/home/user/project',
      },
    ];

    for (const c of cases) {
      expect(ContainerBackend.translateHostPath(c.input, c.platform)).toBe(c.expected);
    }
  });

  it('ContainerBackend never produces legacy /c/... mount format on Windows', () => {
    const windowsPaths = [
      'C:\\Users\\dev\\project',
      'c:\\users\\dev\\project',
      'C:\\Program Files\\Project',
      'd:\\data\\app',
      'D:\\workspace\\test',
    ];
    for (const p of windowsPaths) {
      const translated = ContainerBackend.translateHostPath(p, 'win32');
      expect(translated.startsWith('/c/')).toBe(false);
      expect(translated.startsWith('/d/')).toBe(false);
      expect(/^[a-zA-Z]:\//.test(translated)).toBe(true);
    }
  });

  it('ContainerBackend throws ContainerPathError on invalid or ambiguous host paths (fail-closed)', () => {
    // EMPTY
    expect(() => ContainerBackend.translateHostPath('', 'win32')).toThrow(ContainerPathError);
    expect(() => ContainerBackend.translateHostPath('', 'win32')).toThrowError(
      expect.objectContaining({ code: 'EMPTY' })
    );

    // ILLEGAL_CHARS
    expect(() => ContainerBackend.translateHostPath('C:\\test\0null', 'win32')).toThrowError(
      expect.objectContaining({ code: 'ILLEGAL_CHARS' })
    );
    expect(() => ContainerBackend.translateHostPath('C:\\test*star', 'win32')).toThrowError(
      expect.objectContaining({ code: 'ILLEGAL_CHARS' })
    );
    expect(() => ContainerBackend.translateHostPath('C:\\test?question', 'win32')).toThrowError(
      expect.objectContaining({ code: 'ILLEGAL_CHARS' })
    );
    expect(() => ContainerBackend.translateHostPath('C:\\test"quote', 'win32')).toThrowError(
      expect.objectContaining({ code: 'ILLEGAL_CHARS' })
    );

    // UNC_UNSUPPORTED
    expect(() =>
      ContainerBackend.translateHostPath('\\\\server\\share\\path', 'win32')
    ).toThrowError(expect.objectContaining({ code: 'UNC_UNSUPPORTED' }));
    expect(() =>
      ContainerBackend.translateHostPath('\\\\?\\UNC\\server\\share\\path', 'win32')
    ).toThrowError(expect.objectContaining({ code: 'UNC_UNSUPPORTED' }));
    expect(() =>
      ContainerBackend.translateHostPath('\\\\?\\Unc\\server\\share\\path', 'win32')
    ).toThrowError(expect.objectContaining({ code: 'UNC_UNSUPPORTED' }));
    expect(() => ContainerBackend.translateHostPath('//server/share/path', 'win32')).toThrowError(
      expect.objectContaining({ code: 'UNC_UNSUPPORTED' })
    );

    // DEVICE_PATH_UNSUPPORTED
    expect(() => ContainerBackend.translateHostPath('\\\\.\\pipe\\docker', 'win32')).toThrowError(
      expect.objectContaining({ code: 'DEVICE_PATH_UNSUPPORTED' })
    );

    // DRIVE_RELATIVE
    expect(() => ContainerBackend.translateHostPath('C:', 'win32')).toThrowError(
      expect.objectContaining({ code: 'DRIVE_RELATIVE' })
    );
    expect(() => ContainerBackend.translateHostPath('C:foo', 'win32')).toThrowError(
      expect.objectContaining({ code: 'DRIVE_RELATIVE' })
    );

    // POSIX_STYLE_ON_WINDOWS
    expect(() => ContainerBackend.translateHostPath('/c/Users/x', 'win32')).toThrowError(
      expect.objectContaining({ code: 'POSIX_STYLE_ON_WINDOWS' })
    );
    expect(() => ContainerBackend.translateHostPath('\\Users\\x', 'win32')).toThrowError(
      expect.objectContaining({ code: 'POSIX_STYLE_ON_WINDOWS' })
    );

    // NOT_ABSOLUTE
    expect(() => ContainerBackend.translateHostPath('relative/path', 'win32')).toThrowError(
      expect.objectContaining({ code: 'NOT_ABSOLUTE' })
    );
    expect(() => ContainerBackend.translateHostPath('relative/path', 'linux')).toThrowError(
      expect.objectContaining({ code: 'NOT_ABSOLUTE' })
    );
    expect(() => ContainerBackend.translateHostPath('C:\\Users\\x', 'linux')).toThrowError(
      expect.objectContaining({ code: 'NOT_ABSOLUTE' })
    );
    // Relative path that exists on disk must never be resolved against cwd
    const relativeExistingBackend = new ContainerBackend({
      shadowDir: 'packages',
      config: defaultConfig,
      hostPlatform: 'win32',
    });
    expect(() => relativeExistingBackend.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'NOT_ABSOLUTE' })
    );

    // COLON_IN_PATH
    expect(() => ContainerBackend.translateHostPath('C:\\path\\with:colon', 'win32')).toThrowError(
      expect.objectContaining({ code: 'COLON_IN_PATH' })
    );
    expect(() => ContainerBackend.translateHostPath('/home/user:dir/app', 'linux')).toThrowError(
      expect.objectContaining({ code: 'COLON_IN_PATH' })
    );

    // ROOT_MOUNT_REFUSED
    const rootWinBackend = new ContainerBackend({
      shadowDir: 'C:\\',
      config: defaultConfig,
      hostPlatform: 'win32',
    });
    expect(() => rootWinBackend.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'ROOT_MOUNT_REFUSED' })
    );
    const rootLinuxBackend = new ContainerBackend({
      shadowDir: '/',
      config: defaultConfig,
      hostPlatform: 'linux',
    });
    expect(() => rootLinuxBackend.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'ROOT_MOUNT_REFUSED' })
    );

    // HOME_MOUNT_REFUSED
    const homeWinBackend = new ContainerBackend({
      shadowDir: 'C:\\Users\\dev',
      config: defaultConfig,
      hostPlatform: 'win32',
      homeDir: 'C:\\Users\\dev',
    });
    expect(() => homeWinBackend.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'HOME_MOUNT_REFUSED' })
    );
    const homeAncestorWinBackend = new ContainerBackend({
      shadowDir: 'C:\\Users',
      config: defaultConfig,
      hostPlatform: 'win32',
      homeDir: 'C:\\Users\\dev',
    });
    expect(() => homeAncestorWinBackend.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'HOME_MOUNT_REFUSED' })
    );
    const homeLinuxBackend = new ContainerBackend({
      shadowDir: '/home/dev',
      config: defaultConfig,
      hostPlatform: 'linux',
      homeDir: '/home/dev',
    });
    expect(() => homeLinuxBackend.buildContainerArgs('ls', [])).toThrowError(
      expect.objectContaining({ code: 'HOME_MOUNT_REFUSED' })
    );
  });

  it('ContainerBackend.run propagates ContainerPathError without triggering native fallback or invoking docker run (DEV-1 e)', async () => {
    const backend = new ContainerBackend({
      shadowDir: 'relative/invalid/shadow',
      config: defaultConfig,
      fallbackToNative: true,
      hostPlatform: 'win32',
    });

    const runnerSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      exitCode: 0,
      stdout: 'Docker version 28.0.0',
      stderr: '',
      signal: null,
      durationMs: 5,
      timedOut: false,
      truncated: false,
    });

    await expect(backend.run('node', ['-v'])).rejects.toThrow(ContainerPathError);
    const containerRunCalls = runnerSpy.mock.calls.filter(
      (call) => call[1] && call[1].some((arg) => typeof arg === 'string' && arg.startsWith('-v='))
    );
    expect(containerRunCalls).toHaveLength(0);

    runnerSpy.mockRestore();
  });

  it('ContainerBackend provides container metadata and handles detection gracefully', async () => {
    const backend = new ContainerBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });
    const meta = backend.getMetadata();
    expect(meta.backend).toBe('container');
    // Live detection will check if docker or podman is on PATH
    const available = await backend.isAvailable();
    expect(typeof available).toBe('boolean');
  });

  it('ContainerBackend enforces zero network access in non-install stages (--network=none) (Mutation 14)', () => {
    const backend = new ContainerBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });

    const defaultArgs = backend.buildContainerArgs('npm', ['test'], { network: false });
    expect(defaultArgs).toContain('--network=none');
    expect(defaultArgs).not.toContain('--network=bridge');

    const networkArgs = backend.buildContainerArgs('npm', ['install'], { network: true });
    expect(networkArgs).toContain('--network=bridge');
  });

  it('ContainerBackend drops all capabilities and enforces no-new-privileges (Mutation 15)', () => {
    const backend = new ContainerBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });

    const args = backend.buildContainerArgs('npm', ['test']);
    expect(args).toContain('--cap-drop=ALL');
    expect(args).toContain('--security-opt=no-new-privileges');
  });

  it('ContainerBackend never mounts docker.sock or host home directory (Mutation 16)', () => {
    const expectedTranslatedShadow = 'C:/secureship-shadow-mutation16';
    const backend = new ContainerBackend({
      shadowDir: 'C:\\secureship-shadow-mutation16',
      config: defaultConfig,
      hostPlatform: 'win32',
      realpath: (p: string) => p,
      homeDir: 'C:\\Users\\dev',
    });

    const args = backend.buildContainerArgs('npm', ['test']);
    const mounts = args.filter((a) => a.startsWith('-v=') || a.startsWith('--volume='));
    expect(mounts).toHaveLength(1);
    expect(mounts[0]).toBe(`-v=${expectedTranslatedShadow}:/work:rw`);
    for (const mount of mounts) {
      expect(mount).not.toContain('docker.sock');
      expect(mount).not.toContain(os.homedir());
    }
  });

  it('ContainerBackend passes minimal env and never forwards ambient host environment (Mutation 17)', () => {
    const backend = new ContainerBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });

    const args = backend.buildContainerArgs('npm', ['test']);
    const envVars = args.filter((_a, idx) => args[idx - 1] === '-e');
    expect(envVars).toContain('CI=1');
    expect(envVars).toContain('HOME=/tmp');
    expect(envVars).toContain('LANG=C.UTF-8');
    // Ensure ambient host environment (e.g. USER, USERNAME, PATH) is not dumped into container
    expect(envVars).not.toContain(`USER=${process.env.USER}`);
  });

  it('ContainerBackend cleanup removes labeled containers (Mutation 28)', async () => {
    const { vi } = await import('vitest');
    const { SafeProcessRunner } = await import('../src/runner/safe-process-runner.js');
    const runnerSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      exitCode: 0,
      stdout: '',
      stderr: '',
      signal: null,
      durationMs: 5,
      timedOut: false,
      truncated: false,
    });

    const backend = new ContainerBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });
    // Set resolvedRuntime to test docker cleanup command execution
    (backend as unknown as { resolvedRuntime: string }).resolvedRuntime = 'docker';

    await backend.cleanup();

    expect(runnerSpy).toHaveBeenCalledWith(
      'docker',
      expect.arrayContaining([
        'rm',
        '-f',
        '--filter',
        expect.stringContaining('label=secureship.run='),
      ]),
      expect.objectContaining({ timeoutMs: 5000 })
    );

    runnerSpy.mockRestore();
  });

  it('HostBackend refuses execution on untrusted repository', async () => {
    const backend = new HostBackend({
      repoDir: tempDir,
      shadowDir: tempDir,
      config: defaultConfig, // trustedHostRepos is empty
    });

    expect(backend.isRepoTrusted()).toBe(false);
    await expect(backend.run('node', ['-v'])).rejects.toThrow(/not trusted for host execution/);
  });

  it('HostBackend executes on trusted repository with HOST EXECUTION banner', async () => {
    const repoHash = HostBackend.computeRepoHash(tempDir);
    const trustedConfig = SandboxConfigSchema.parse({
      backend: 'host',
      trustedHostRepos: [repoHash],
    });

    const backend = new HostBackend({
      repoDir: tempDir,
      shadowDir: tempDir,
      config: trustedConfig,
    });

    expect(backend.isRepoTrusted()).toBe(true);
    const res = await backend.run('node', ['-e', 'console.log("hello host")']);
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('HOST EXECUTION: NOT A SANDBOX');
    expect(res.stdout).toContain('hello host');
  });

  it('FakeSandboxBackend records runs and returns scripted responses', async () => {
    const fake = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'custom default' },
    });
    expect(await fake.isAvailable()).toBe(true);
    expect(fake.getMetadata().backend).toBe('none');

    fake.scriptResponse('TEST', {
      exitCode: 1,
      stderr: 'Test assertion failed',
    });

    const run1 = await fake.run('npm', ['test'], { stageName: 'TEST' });
    expect(run1.exitCode).toBe(1);
    expect(run1.stderr).toBe('Test assertion failed');

    // Run without stageName to exercise fallback to command name
    const run2 = await fake.run('build-cmd', ['--prod']);
    expect(run2.exitCode).toBe(0);
    expect(run2.stdout).toBe('custom default');

    // Test reset and setDefaultResponse
    fake.setDefaultResponse({ exitCode: 2, timedOut: true });
    const run3 = await fake.run('check', []);
    expect(run3.exitCode).toBe(2);
    expect(run3.timedOut).toBe(true);

    fake.reset();
    expect(fake.recordedRuns).toHaveLength(0);
    await fake.cleanup();
  });

  it('ContainerBackend.run throws when no container runtime is available', async () => {
    const backend = new ContainerBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });
    vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      exitCode: 1,
      stdout: '',
      stderr: 'not found',
      signal: null,
      durationMs: 5,
      timedOut: false,
      truncated: false,
    });
    await expect(backend.run('node', ['-v'])).rejects.toThrow(/No container runtime/);
    vi.restoreAllMocks();
  });

  it('ContainerBackend.run executes command via runtime and redacts secrets', async () => {
    const backend = new ContainerBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });
    const spy = vi
      .spyOn(SafeProcessRunner, 'run')
      .mockResolvedValueOnce({
        exitCode: 0,
        stdout: 'Docker version 27.0.0',
        stderr: '',
        signal: null,
        durationMs: 5,
        timedOut: false,
        truncated: false,
      })
      .mockResolvedValueOnce({
        exitCode: 0,
        stdout: 'Ran tests with ghp_123456789012345678901234567890123456',
        stderr: '',
        signal: null,
        durationMs: 50,
        timedOut: false,
        truncated: false,
      });

    const res = await backend.run('npm', ['test'], { env: { CI: 'true' } });
    expect(res.exitCode).toBe(0);
    expect(res.outputTail).toContain('[REDACTED]');
    expect(res.outputTail).not.toContain('ghp_123456789012345678901234567890123456');

    // Test cleanup
    await backend.cleanup();
    expect(spy).toHaveBeenCalled();
    vi.restoreAllMocks();
  });

  it('ContainerBackend.isDaemonActive detects daemon status via info command', async () => {
    const backend = new ContainerBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });

    vi.spyOn(SafeProcessRunner, 'run')
      .mockResolvedValueOnce({
        exitCode: 0,
        stdout: 'Docker version 28.0.0',
        stderr: '',
        signal: null,
        durationMs: 5,
        timedOut: false,
        truncated: false,
      })
      .mockResolvedValueOnce({
        exitCode: 0,
        stdout: 'Server Version: 28.0.0',
        stderr: '',
        signal: null,
        durationMs: 10,
        timedOut: false,
        truncated: false,
      });

    const active = await backend.isDaemonActive();
    expect(active).toBe(true);
    vi.restoreAllMocks();
  });

  it('ContainerBackend with fallbackToNative delegates seamlessly to NativeIsolatedBackend when daemon is down', async () => {
    const backend = new ContainerBackend({
      shadowDir: tempDir,
      config: defaultConfig,
      fallbackToNative: true,
    });

    // Mock: docker version succeeds, but docker info fails (daemon inactive)
    vi.spyOn(SafeProcessRunner, 'run')
      .mockResolvedValueOnce({
        exitCode: 0,
        stdout: 'Docker version 28.0.0',
        stderr: '',
        signal: null,
        durationMs: 5,
        timedOut: false,
        truncated: false,
      })
      .mockResolvedValueOnce({
        exitCode: 1,
        stdout: '',
        stderr: 'failed to connect to docker API',
        signal: null,
        durationMs: 10,
        timedOut: false,
        truncated: false,
      })
      // Third call will be the NativeIsolated execution
      .mockResolvedValueOnce({
        exitCode: 0,
        stdout: 'test passed in native shadow sandbox',
        stderr: '',
        signal: null,
        durationMs: 20,
        timedOut: false,
        truncated: false,
      });

    const res = await backend.run(process.execPath, ['-v']);
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('NATIVE ISOLATED SHADOW SANDBOX');
    expect(backend.getMetadata().backend).toBe('native-isolated');

    await backend.cleanup();
    vi.restoreAllMocks();
  });
});
