import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { ConfigSchema, type SecureShipConfig } from '@secureship/contracts';

export class ConfigLoader {
  /**
   * Loads and validates secureship.config.json from path or workspace root.
   */
  public static loadConfig(workspaceRoot: string, explicitConfigPath?: string): SecureShipConfig {
    const configPath = explicitConfigPath
      ? path.resolve(explicitConfigPath)
      : path.join(workspaceRoot, 'secureship.config.json');

    if (!existsSync(configPath)) {
      if (explicitConfigPath) {
        throw new Error(`Explicit config file not found: ${configPath}`);
      }
      // Return default config
      return ConfigSchema.parse({});
    }

    let parsedJson: unknown;
    try {
      const content = readFileSync(configPath, 'utf-8');
      parsedJson = JSON.parse(content);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to parse config file at '${configPath}': ${msg}`);
    }

    if (parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
      const obj = parsedJson as Record<string, unknown>;
      if ('ai' in obj) {
        console.warn(
          `[SECURITY WARNING] Repository config at '${configPath}' contains forbidden key 'ai'. AI configuration may only be specified in per-user config (~/.secureship/), CLI flags, or environment variables. Ignoring 'ai'.`
        );
        delete obj.ai;
      }
      if ('gate3' in obj) {
        console.warn(
          `[SECURITY WARNING] Repository config at '${configPath}' contains forbidden key 'gate3'. Gate 3 configuration may only be specified in per-user config (~/.secureship/), CLI flags, or environment variables. Ignoring 'gate3'.`
        );
        delete obj.gate3;
      }
      if ('sandbox' in obj) {
        console.warn(
          `[SECURITY WARNING] Repository config at '${configPath}' contains forbidden key 'sandbox'. Sandbox configuration may only be specified in per-user config (~/.secureship/), CLI flags, or environment variables. Ignoring 'sandbox'.`
        );
        delete obj.sandbox;
      }
      if ('reachability' in obj) {
        console.warn(
          `[SECURITY WARNING] Repository config at '${configPath}' contains forbidden key 'reachability'. Reachability configuration may only be specified in per-user config (~/.secureship/), CLI flags, or environment variables. Ignoring 'reachability'.`
        );
        delete obj.reachability;
      }
      if ('symbolDataset' in obj) {
        console.warn(
          `[SECURITY WARNING] Repository config at '${configPath}' contains forbidden key 'symbolDataset'. Symbol dataset paths may only be specified in per-user config (~/.secureship/) or CLI flags. Ignoring 'symbolDataset'.`
        );
        delete obj.symbolDataset;
      }
    }

    const validation = ConfigSchema.safeParse(parsedJson);
    if (!validation.success) {
      throw new Error(`Invalid configuration in '${configPath}': ${validation.error.message}`);
    }

    return validation.data;
  }
}
