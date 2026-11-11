import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { UserConfigSchema, type UserConfig } from '@secureship/contracts';

export interface CliAiOverrides {
  ai?: boolean;
  gate3Mode?: 'off' | 'annotate' | 'suppress';
  provider?: 'anthropic' | 'openai' | 'fake';
  model?: string;
  baseUrl?: string;
  maxFindings?: number;
  budgetTokens?: number;
  concurrency?: number;
}

export class UserConfigLoader {
  /**
   * Resolves the per-user SecureShip configuration directory.
   */
  public static getUserConfigDir(): string {
    return process.platform === 'win32'
      ? process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, 'secureship')
        : path.join(os.homedir(), '.secureship')
      : process.env.XDG_CONFIG_HOME
        ? path.join(process.env.XDG_CONFIG_HOME, 'secureship')
        : path.join(os.homedir(), '.secureship');
  }

  /**
   * Resolves the user config.json path.
   */
  public static getUserConfigPath(): string {
    return path.join(UserConfigLoader.getUserConfigDir(), 'config.json');
  }

  /**
   * Loads UserConfig strictly from per-user directory, env, and CLI flags (A1).
   * Never loads .env from the scan target.
   */
  public static loadUserConfig(
    cliOverrides: CliAiOverrides = {},
    explicitConfigPath?: string
  ): UserConfig {
    const configPath = explicitConfigPath || UserConfigLoader.getUserConfigPath();

    let diskConfig: Record<string, unknown> = {};
    if (fs.existsSync(configPath)) {
      try {
        const raw = fs.readFileSync(configPath, 'utf-8');
        diskConfig = JSON.parse(raw);
      } catch {
        // Fall back to empty disk config if unparseable
      }
    }

    // Merge environment variables
    const envProvider = process.env.SECURESHIP_AI_PROVIDER as
      | 'anthropic'
      | 'openai'
      | 'fake'
      | undefined;
    const envModel = process.env.SECURESHIP_AI_MODEL;
    const envBaseUrl = process.env.SECURESHIP_AI_BASE_URL;

    // Merge CLI overrides
    const merged: Record<string, unknown> = {
      ...diskConfig,
      enabled: cliOverrides.ai ?? diskConfig.enabled ?? diskConfig.ai ?? false,
      ai: cliOverrides.ai ?? diskConfig.ai ?? diskConfig.enabled ?? false,
      provider: cliOverrides.provider ?? envProvider ?? diskConfig.provider,
      model: cliOverrides.model ?? envModel ?? diskConfig.model,
      baseUrl: cliOverrides.baseUrl ?? envBaseUrl ?? diskConfig.baseUrl,
      gate3: {
        ...((diskConfig.gate3 as Record<string, unknown>) || {}),
        mode:
          cliOverrides.gate3Mode ??
          ((diskConfig.gate3 as Record<string, unknown>)?.mode as string) ??
          'annotate',
        maxFindings:
          cliOverrides.maxFindings ??
          ((diskConfig.gate3 as Record<string, unknown>)?.maxFindings as number) ??
          25,
        budgetTokens:
          cliOverrides.budgetTokens ??
          ((diskConfig.gate3 as Record<string, unknown>)?.budgetTokens as number) ??
          200_000,
        concurrency:
          cliOverrides.concurrency ??
          ((diskConfig.gate3 as Record<string, unknown>)?.concurrency as number) ??
          2,
      },
    };

    return UserConfigSchema.parse(merged);
  }

  /**
   * Resolves API key for a provider without exposing it to CLI flags (A2).
   * Checks provider-specific environment variables, generic SECURESHIP_AI_API_KEY,
   * or user-level 0600 key file.
   */
  public static resolveApiKey(provider: string): string | undefined {
    // 1. Provider-specific env var
    if (provider === 'anthropic' && process.env.ANTHROPIC_API_KEY) {
      return process.env.ANTHROPIC_API_KEY.trim();
    }
    if (provider === 'openai' && process.env.OPENAI_API_KEY) {
      return process.env.OPENAI_API_KEY.trim();
    }

    // 2. Generic SecureShip env var
    if (process.env.SECURESHIP_AI_API_KEY) {
      return process.env.SECURESHIP_AI_API_KEY.trim();
    }

    // 3. User-level 0600 file (~/.secureship/ai-key or ~/.secureship/<provider>.key)
    const baseDir = UserConfigLoader.getUserConfigDir();
    const keyCandidates = [path.join(baseDir, `${provider}.key`), path.join(baseDir, 'ai-key')];

    for (const keyPath of keyCandidates) {
      if (fs.existsSync(keyPath)) {
        try {
          const content = fs.readFileSync(keyPath, 'utf-8').trim();
          if (content.length > 0) {
            return content;
          }
        } catch {
          // Continue searching
        }
      }
    }

    return undefined;
  }

  /**
   * Saves UserConfig to the user configuration directory with 0600 permissions.
   */
  public static saveUserConfig(config: UserConfig, explicitPath?: string): void {
    const configPath = explicitPath || UserConfigLoader.getUserConfigPath();
    const dir = path.dirname(configPath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });
    if (process.platform !== 'win32') {
      try {
        fs.chmodSync(configPath, 0o600);
      } catch {}
    }
  }
}
