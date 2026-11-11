import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { ConfigLoader } from '../src/config/load-config.js';

describe('ConfigLoader Unit Suite', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(path.join(tmpdir(), 'secureship-config-test-'));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('returns default config when secureship.config.json is absent', () => {
    const config = ConfigLoader.loadConfig(tempDir);
    expect(config).toBeDefined();
    expect(config.failOn).toBe('HIGH');
    expect(config.gate1?.keepProviderSecrets).toBe(true);
  });

  it('throws helpful error when explicit config path does not exist', () => {
    const missingPath = path.join(tempDir, 'nonexistent.json');
    expect(() => ConfigLoader.loadConfig(tempDir, missingPath)).toThrow(
      'Explicit config file not found'
    );
  });

  it('throws clean error on invalid JSON syntax in config', () => {
    const invalidJsonPath = path.join(tempDir, 'secureship.config.json');
    writeFileSync(invalidJsonPath, '{ invalid json: true', 'utf-8');

    expect(() => ConfigLoader.loadConfig(tempDir)).toThrow('Failed to parse config file');
  });

  it('throws clean error on schema violation in config', () => {
    const invalidSchemaPath = path.join(tempDir, 'secureship.config.json');
    writeFileSync(
      invalidSchemaPath,
      JSON.stringify({
        failOn: 'INVALID_SEVERITY',
      }),
      'utf-8'
    );

    expect(() => ConfigLoader.loadConfig(tempDir)).toThrow('Invalid configuration');
  });

  it('successfully loads and validates full custom configuration', () => {
    const configPath = path.join(tempDir, 'custom.config.json');
    writeFileSync(
      configPath,
      JSON.stringify({
        failOn: 'CRITICAL',
        scanners: {
          opengrep: true,
          gitleaks: false,
        },
        timeouts: {
          default: 45000,
          opengrep: 60000,
        },
        gate1: {
          enabled: true,
          keepProviderSecrets: true,
          customTestDirs: ['custom_tests'],
        },
        ignore: [
          {
            ruleId: 'SEC-101',
            reason: 'Reviewed by security team and accepted risk for testing',
            expires: '2026-12-31',
          },
        ],
      }),
      'utf-8'
    );

    const config = ConfigLoader.loadConfig(tempDir, configPath);
    expect(config.failOn).toBe('CRITICAL');
    expect(config.scanners?.opengrep).toBe(true);
    expect(config.scanners?.gitleaks).toBe(false);
    expect(config.timeouts?.opengrep).toBe(60000);
    expect(config.gate1?.customTestDirs).toContain('custom_tests');
    expect(config.ignore).toHaveLength(1);
    expect(config.ignore![0]!.ruleId).toBe('SEC-101');
  });

  it('ignores forbidden ai and gate3 keys in repo config with security warning (A1)', () => {
    const configPath = path.join(tempDir, 'secureship.config.json');
    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    writeFileSync(
      configPath,
      JSON.stringify({
        failOn: 'HIGH',
        ai: {
          enabled: true,
          baseUrl: 'http://localhost:9999',
          provider: 'openai',
        },
        gate3: {
          mode: 'suppress',
        },
        sandbox: {
          backend: 'host',
        },
        reachability: {
          functionLevel: 'off',
        },
        symbolDataset: '/etc/passwd',
      }),
      'utf-8'
    );

    const config = ConfigLoader.loadConfig(tempDir);
    expect(config.failOn).toBe('HIGH');
    expect((config as Record<string, unknown>).ai).toBeUndefined();
    expect((config as Record<string, unknown>).gate3).toBeUndefined();
    expect((config as Record<string, unknown>).sandbox).toBeUndefined();
    expect((config as Record<string, unknown>).reachability).toBeUndefined();
    expect((config as Record<string, unknown>).symbolDataset).toBeUndefined();
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining("contains forbidden key 'ai'")
    );
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining("contains forbidden key 'gate3'")
    );
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining("contains forbidden key 'sandbox'")
    );
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining("contains forbidden key 'reachability'")
    );
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining("contains forbidden key 'symbolDataset'")
    );

    consoleWarnSpy.mockRestore();
  });

  it('canary server test: repo config trying to enable AI or baseUrl produces ZERO requests (A1)', async () => {
    const http = await import('node:http');
    let requestCount = 0;

    const canaryServer = http.createServer((_req, res) => {
      requestCount++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });

    await new Promise<void>((resolve) => canaryServer.listen(0, '127.0.0.1', () => resolve()));
    const address = canaryServer.address() as { port: number };
    const canaryUrl = `http://127.0.0.1:${address.port}/v1`;

    try {
      const configPath = path.join(tempDir, 'secureship.config.json');
      writeFileSync(
        configPath,
        JSON.stringify({
          ai: {
            enabled: true,
            baseUrl: canaryUrl,
          },
          gate3: {
            mode: 'suppress',
          },
        }),
        'utf-8'
      );

      // Loading config strips ai and gate3
      const loaded = ConfigLoader.loadConfig(tempDir);
      expect((loaded as Record<string, unknown>).ai).toBeUndefined();
      expect((loaded as Record<string, unknown>).gate3).toBeUndefined();

      // Ensure zero requests were made to canary server
      expect(requestCount).toBe(0);
    } finally {
      await new Promise<void>((resolve) => canaryServer.close(() => resolve()));
    }
  });
});
