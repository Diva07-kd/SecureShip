import { existsSync, statSync, realpathSync } from 'node:fs';
import { execSync } from 'node:child_process';
import path from 'node:path';
import { platform } from 'node:os';
import type { ScannerName } from '@secureship/contracts';
import { resolveToolDirs, assertNotInsideTarget } from './paths.js';

export interface BinaryResolverOptions {
  explicitBinDir?: string;
}

export class BinaryResolver {
  private static readonly isWindows = platform() === 'win32';

  /**
   * Resolves a binary by name, checking config overrides first, then SecureShip tool dirs and system PATH.
   * Enforces security barrier: binary can NEVER reside inside targetDir.
   */
  public static resolve(
    scannerName: ScannerName | string,
    targetDir: string,
    overrides?: Partial<Record<string, string>>,
    options?: BinaryResolverOptions
  ): string | null {
    // 1. Check explicit override
    if (overrides && overrides[scannerName]) {
      const overridePath = overrides[scannerName]!;
      if (existsSync(overridePath)) {
        BinaryResolver.assertNotInsideTarget(overridePath, targetDir);
        return path.resolve(overridePath);
      }
      return null;
    }

    // 2. Resolve across SecureShip tool dirs and system PATH
    const resolved = BinaryResolver.resolveOnPath(scannerName, options);
    if (!resolved) {
      return null;
    }

    // 3. Security guard against planted-binary attacks
    BinaryResolver.assertNotInsideTarget(resolved, targetDir);

    return resolved;
  }

  private static userPathWindowsCache: string[] | null = null;

  public static getUserPathWindows(): string[] {
    if (!BinaryResolver.isWindows) return [];
    if (BinaryResolver.userPathWindowsCache !== null) {
      return BinaryResolver.userPathWindowsCache;
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
    BinaryResolver.userPathWindowsCache = dirs;
    return dirs;
  }

  /**
   * Resolves binary name across SecureShip candidate directories and system PATH, honoring Windows PATHEXT.
   */
  public static resolveOnPath(name: string, options?: BinaryResolverOptions): string | null {
    const rawPath = process.env.PATH ?? '';
    const delimiter = BinaryResolver.isWindows ? ';' : ':';
    const envDirs = rawPath.split(delimiter).filter(Boolean);
    const userDirs = BinaryResolver.getUserPathWindows();

    // Central tool directories in precedence order:
    // explicitDir -> SECURESHIP_BIN_DIR -> /opt/secureship/bin -> <SECURESHIP_HOME>/bin
    const secureshipToolDirs = resolveToolDirs({ explicitDir: options?.explicitBinDir });

    const dirs = Array.from(new Set([...secureshipToolDirs, ...envDirs, ...userDirs]));

    const extensions = BinaryResolver.isWindows
      ? (process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').map((e) => e.toLowerCase())
      : [''];

    for (const dir of dirs) {
      for (const ext of extensions) {
        const full = path.join(
          dir,
          BinaryResolver.isWindows && !name.toLowerCase().endsWith(ext) ? `${name}${ext}` : name
        );
        try {
          if (existsSync(full)) {
            const stat = statSync(full);
            if (stat.isFile()) {
              try {
                return realpathSync(full);
              } catch {
                return path.resolve(full);
              }
            }
          }
        } catch {
          // Ignore filesystem or permission errors
        }
      }
    }

    return null;
  }

  /**
   * Enforces that binary is NOT inside the scanned target directory.
   * Prevents planted-binary attacks where a malicious repository contains e.g. ./gitleaks.exe
   */
  public static assertNotInsideTarget(binaryPath: string, targetDir: string): void {
    assertNotInsideTarget(binaryPath, targetDir);
  }
}
