import fs from 'node:fs';
import path from 'node:path';

export interface StandaloneExecEnv {
  execPath?: string;
  bunVersion?: string | undefined;
  realpath?: (p: string) => string;
}

/**
 * Returns the absolute directory containing the currently executing standalone binary,
 * or null if the process is not running as a standalone Bun-compiled executable.
 *
 * Why __dirname / import.meta.url are unusable inside Bun-compiled binaries:
 * When Bun compiles an application into a standalone executable (`bun build --compile`),
 * JavaScript and TypeScript assets are bundled into Bun's internal virtual filesystem
 * (e.g. `B:\~BUN\root` on Windows, or `/$bunfs/root` on Linux/macOS). Consequently,
 * `import.meta.url` and `__dirname` evaluate to virtual filesystem URLs/paths rather
 * than physical disk locations. Attempting to locate external companion directories
 * (such as `wasm/`, `data/`, or `rules/`) relative to `import.meta.url` or `__dirname`
 * fails because those assets reside on the host filesystem next to the executable binary,
 * not inside the virtual filesystem.
 *
 * Standalone detection:
 * - `process.versions.bun` is set AND
 * - `path.basename(execPath, path.extname(execPath))` is neither `bun` nor `node`.
 *
 * Symlink safety:
 * When running as a standalone binary, resolves symlinks via `fs.realpathSync`.
 * If `realpath` fails, gracefully falls back to `path.dirname(execPath)`.
 * This function is pure, injectable for testing, and never throws.
 */
export function getStandaloneExecDir(env?: StandaloneExecEnv): string | null {
  try {
    const execPath = env?.execPath ?? process.execPath;
    if (!execPath) return null;

    const bunVersion = env?.bunVersion !== undefined ? env.bunVersion : process.versions?.bun;
    if (!bunVersion) return null;

    const ext = path.extname(execPath);
    const baseName = path.basename(execPath, ext).toLowerCase();
    if (baseName === 'bun' || baseName === 'node') {
      return null;
    }

    const realpathFn = env?.realpath ?? fs.realpathSync;
    try {
      const resolvedPath = realpathFn(execPath);
      return path.dirname(resolvedPath);
    } catch {
      return path.dirname(execPath);
    }
  } catch {
    return null;
  }
}
