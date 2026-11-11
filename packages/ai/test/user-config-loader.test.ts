import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { UserConfigSchema } from '@secureship/contracts';
import { UserConfigLoader } from '../src/user-config/user-config-loader.js';

describe('UserConfigLoader Unit Suite (A1, A2)', () => {
  let tempDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-user-config-test-'));
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('resolves user config dir and config path', () => {
    const dir = UserConfigLoader.getUserConfigDir();
    const confPath = UserConfigLoader.getUserConfigPath();
    expect(dir.length).toBeGreaterThan(0);
    expect(confPath).toContain('config.json');
  });

  it('loads default config when file does not exist', () => {
    const fakePath = path.join(tempDir, 'non-existent.json');
    const config = UserConfigLoader.loadUserConfig({}, fakePath);
    expect(config.enabled).toBe(false);
    expect(config.gate3.mode).toBe('annotate');
    expect(config.gate3.concurrency).toBe(2);
  });

  it('merges disk config, environment variables, and CLI overrides', () => {
    const confPath = path.join(tempDir, 'config.json');
    UserConfigLoader.saveUserConfig(
      UserConfigSchema.parse({
        enabled: true,
        ai: true,
        provider: 'anthropic',
        model: 'claude-3-5-sonnet',
        baseUrl: 'https://api.anthropic.com/v1',
        gate3: {
          mode: 'annotate',
          neverSuppressSeverities: ['CRITICAL', 'HIGH'],
          minConfidence: 'HIGH',
          consistencyChecks: 2,
          maxFindings: 15,
          budgetTokens: 150_000,
          sliceTokens: 5000,
          concurrency: 2,
        },
      }),
      confPath
    );

    // Override with environment variable
    process.env.SECURESHIP_AI_MODEL = 'claude-3-7-sonnet';

    // Override with CLI flag
    const merged = UserConfigLoader.loadUserConfig(
      {
        provider: 'openai',
        gate3Mode: 'suppress',
        concurrency: 4,
      },
      confPath
    );

    expect(merged.enabled).toBe(true);
    expect(merged.provider).toBe('openai'); // CLI override wins
    expect(merged.model).toBe('claude-3-7-sonnet'); // Env override applied
    expect(merged.gate3.mode).toBe('suppress'); // CLI override
    expect(merged.gate3.concurrency).toBe(4);
    expect(merged.gate3.maxFindings).toBe(15);
  });

  it('resolves API key from provider env, generic env, or local key file (A2)', () => {
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.SECURESHIP_AI_API_KEY;

    // 1. Provider-specific env
    process.env.ANTHROPIC_API_KEY = 'ant-key-123';
    expect(UserConfigLoader.resolveApiKey('anthropic')).toBe('ant-key-123');

    // 2. OpenAI env
    process.env.OPENAI_API_KEY = 'oa-key-456';
    expect(UserConfigLoader.resolveApiKey('openai')).toBe('oa-key-456');

    // 3. Generic SecureShip env
    delete process.env.OPENAI_API_KEY;
    process.env.SECURESHIP_AI_API_KEY = 'generic-key-789';
    expect(UserConfigLoader.resolveApiKey('openai')).toBe('generic-key-789');

    // 4. Undefined when nothing is set
    delete process.env.SECURESHIP_AI_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    expect(UserConfigLoader.resolveApiKey('fake')).toBeUndefined();
  });
});
