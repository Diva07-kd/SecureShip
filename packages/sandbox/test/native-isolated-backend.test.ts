import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { NativeIsolatedBackend } from '../src/backends/native-isolated-backend.js';
import { SandboxConfigSchema } from '@secureship/contracts';

describe('NativeIsolatedBackend Suite', () => {
  let tempDir: string;
  const defaultConfig = SandboxConfigSchema.parse({});

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-native-iso-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('provides native-isolated metadata and is available by default', async () => {
    const backend = new NativeIsolatedBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });

    expect(backend.name).toBe('native-isolated');
    expect(await backend.isAvailable()).toBe(true);
    const meta = backend.getMetadata();
    expect(meta.backend).toBe('native-isolated');
    expect(meta.networkIsolated).toBe(true);
    expect(meta.isolation).toBe('shadow-airgap');
  });

  it('builds dead-loopback proxy and ecosystem offline flags for 99% of languages', () => {
    const offlineEnv = NativeIsolatedBackend.buildNetworkIsolationEnv(false);

    // Universal proxies
    expect(offlineEnv.HTTP_PROXY).toBe('http://127.0.0.1:0');
    expect(offlineEnv.HTTPS_PROXY).toBe('http://127.0.0.1:0');
    expect(offlineEnv.ALL_PROXY).toBe('socks5://127.0.0.1:0');
    expect(offlineEnv.NO_PROXY).toBe('');

    // Node ecosystem
    expect(offlineEnv.npm_config_proxy).toBe('http://127.0.0.1:0');
    expect(offlineEnv.npm_config_offline).toBe('true');
    expect(offlineEnv.YARN_OFFLINE).toBe('true');

    // Python ecosystem
    expect(offlineEnv.PIP_PROXY).toBe('http://127.0.0.1:0');
    expect(offlineEnv.PIP_NO_INDEX).toBe('true');
    expect(offlineEnv.PIP_ISOLATED).toBe('1');

    // Rust ecosystem
    expect(offlineEnv.CARGO_NET_OFFLINE).toBe('true');

    // Go ecosystem
    expect(offlineEnv.GOPROXY).toBe('off');

    // Java ecosystem
    expect(offlineEnv.MAVEN_OPTS).toContain('offline=true');
    expect(offlineEnv.GRADLE_OPTS).toContain('offline=true');

    // .NET ecosystem
    expect(offlineEnv.DOTNET_CLI_TELEMETRY_OPTOUT).toBe('1');
    expect(offlineEnv.NUGET_CERT_REVOCATION_MODE).toBe('offline');

    // Ruby ecosystem
    expect(offlineEnv.BUNDLE_LOCAL).toBe('true');
  });

  it('allows network when allowNetwork is true for install stage', () => {
    const installEnv = NativeIsolatedBackend.buildNetworkIsolationEnv(true);
    expect(installEnv.HTTP_PROXY).toBeUndefined();
    expect(installEnv.npm_config_proxy).toBeUndefined();
    expect(installEnv.GOPROXY).toBeUndefined();
    expect(installEnv.CARGO_NET_OFFLINE).toBeUndefined();
  });

  it('executes command safely in shadow directory with banner and output hashing', async () => {
    const backend = new NativeIsolatedBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });

    const res = await backend.run(process.execPath, [
      '-e',
      'console.log("hello from native isolated sandbox")',
    ]);

    expect(res.exitCode).toBe(0);
    expect(res.timedOut).toBe(false);
    expect(res.stdout).toContain('--- NATIVE ISOLATED SHADOW SANDBOX');
    expect(res.stdout).toContain('hello from native isolated sandbox');
    expect(res.outputSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(res.durationMs).toBeGreaterThan(0);
  });

  it('redacts secrets from stdout and outputTail', async () => {
    const backend = new NativeIsolatedBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });

    const res = await backend.run(process.execPath, [
      '-e',
      'console.log("Token: ghp_123456789012345678901234567890123456")',
    ]);

    expect(res.exitCode).toBe(0);
    expect(res.outputTail).toContain('[REDACTED]');
    expect(res.outputTail).not.toContain('ghp_123456789012345678901234567890123456');
  });

  it('enforces execution timeout', async () => {
    const backend = new NativeIsolatedBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });

    const res = await backend.run(process.execPath, ['-e', 'setTimeout(() => {}, 15000)'], {
      timeoutMs: 300,
    });

    expect(res.timedOut).toBe(true);
  });

  it('resolves commands safely on Windows without shell invocation', () => {
    const resolved = NativeIsolatedBackend.resolveCommand('node', ['-v']);
    expect(resolved.executable).toBeTruthy();
    expect(resolved.args).toEqual(['-v']);
  });

  it('cleans up resources cleanly', async () => {
    const backend = new NativeIsolatedBackend({
      shadowDir: tempDir,
      config: defaultConfig,
    });

    await expect(backend.cleanup()).resolves.toBeUndefined();
  });
});
