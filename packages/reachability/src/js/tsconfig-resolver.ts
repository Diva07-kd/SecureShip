import fs from 'node:fs';
import path from 'node:path';

export interface TsConfigPaths {
  baseUrl?: string;
  paths?: Record<string, string[]>;
}

export class TsConfigResolver {
  /**
   * Loads tsconfig.json compilerOptions (baseUrl and paths), safely enforcing root bounds.
   */
  public static load(projectRoot: string, customConfigPath?: string): TsConfigPaths {
    const configPath = customConfigPath
      ? path.isAbsolute(customConfigPath)
        ? customConfigPath
        : path.resolve(projectRoot, customConfigPath)
      : path.join(projectRoot, 'tsconfig.json');

    if (!fs.existsSync(configPath)) {
      return {};
    }

    try {
      // Security check: configPath must reside within projectRoot
      const realRoot = fs.realpathSync(projectRoot);
      const realConfig = fs.realpathSync(configPath);
      const rel = path.relative(realRoot, realConfig);
      if (rel.startsWith('..') || path.isAbsolute(rel)) {
        return {}; // Escape attempt blocked
      }

      const content = fs.readFileSync(configPath, 'utf8');
      // Strip comments (single-line // and multi-line /* ... */)
      const cleanJson = content.replace(/\/\*[\s\S]*?\*\/|([^:]|^)\/\/.*$/gm, '$1');
      const parsed = JSON.parse(cleanJson);

      const compilerOptions = parsed.compilerOptions ?? {};
      const baseUrl = compilerOptions.baseUrl
        ? path.resolve(projectRoot, compilerOptions.baseUrl)
        : projectRoot;

      // Ensure baseUrl does not escape projectRoot
      const relBase = path.relative(realRoot, baseUrl);
      const safeBaseUrl = relBase.startsWith('..') ? realRoot : baseUrl;

      const rawPaths: Record<string, string[]> = compilerOptions.paths ?? {};
      const safePaths: Record<string, string[]> = {};

      for (const [aliasPattern, targetPatterns] of Object.entries(rawPaths)) {
        safePaths[aliasPattern] = (targetPatterns as string[]).map((tp) => {
          // Normalize forward slashes
          return tp.replace(/\\/g, '/');
        });
      }

      return {
        baseUrl: safeBaseUrl,
        paths: safePaths,
      };
    } catch {
      return {};
    }
  }

  /**
   * Attempts to resolve an aliased import specifier using tsconfig baseUrl and paths.
   */
  public static resolveAlias(
    specifier: string,
    tsconfig: TsConfigPaths,
    projectRoot: string
  ): string | null {
    if (!tsconfig.paths && !tsconfig.baseUrl) return null;

    const realRoot = fs.realpathSync(projectRoot);

    // 1. Check paths mappings
    if (tsconfig.paths) {
      for (const [pattern, targets] of Object.entries(tsconfig.paths)) {
        const starIdx = pattern.indexOf('*');
        if (starIdx !== -1) {
          const prefix = pattern.slice(0, starIdx);
          const suffix = pattern.slice(starIdx + 1);

          if (specifier.startsWith(prefix) && specifier.endsWith(suffix)) {
            const matchedStar = specifier.slice(prefix.length, specifier.length - suffix.length);

            for (const target of targets) {
              const replacedTarget = target.replace('*', matchedStar);
              const candidate = path.resolve(tsconfig.baseUrl ?? projectRoot, replacedTarget);

              // Guard against path escaping root
              const rel = path.relative(realRoot, candidate);
              if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
                return candidate;
              }
            }
          }
        } else if (specifier === pattern) {
          for (const target of targets) {
            const candidate = path.resolve(tsconfig.baseUrl ?? projectRoot, target);
            const rel = path.relative(realRoot, candidate);
            if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
              return candidate;
            }
          }
        }
      }
    }

    // 2. Check baseUrl direct resolution if baseUrl was explicitly set
    if (tsconfig.baseUrl && tsconfig.baseUrl !== projectRoot) {
      const candidate = path.resolve(tsconfig.baseUrl, specifier);
      const rel = path.relative(realRoot, candidate);
      if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
        const extensions = ['', '.ts', '.tsx', '.js', '.jsx', '.json'];
        const exists =
          extensions.some((ext) => fs.existsSync(candidate + ext)) ||
          fs.existsSync(path.join(candidate, 'index.ts')) ||
          fs.existsSync(path.join(candidate, 'index.js'));
        if (exists) {
          return candidate;
        }
      }
    }

    return null;
  }
}
