import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

/**
 * Returns the SecureShip root configuration and data home directory.
 * Honors SECURESHIP_HOME environment variable, falling back to ~/.secureship.
 */
export function resolveSecureshipHome(): string {
  const env = process.env.SECURESHIP_HOME?.trim();
  if (env && env.length > 0) {
    return path.resolve(env);
  }
  return path.join(os.homedir(), '.secureship');
}

export interface ResolveToolDirsOptions {
  explicitDir?: string;
  targetDir?: string;
}

/**
 * Resolves tool search directories in strict precedence order:
 * 1. Explicitly provided directory (CLI flag / options)
 * 2. SECURESHIP_BIN_DIR environment variable
 * 3. Immutable system tool directory (/opt/secureship/bin) if present
 * 4. User directory (<SECURESHIP_HOME>/bin)
 *
 * If targetDir is specified, enforces that none of the tool directories reside inside targetDir.
 */
export function resolveToolDirs(options: ResolveToolDirsOptions = {}): string[] {
  const dirs: string[] = [];

  // 1. Explicit directory argument
  if (options.explicitDir && options.explicitDir.trim().length > 0) {
    dirs.push(path.resolve(options.explicitDir.trim()));
  }

  // 2. SECURESHIP_BIN_DIR environment variable
  const envBin = process.env.SECURESHIP_BIN_DIR;
  if (envBin && envBin.trim().length > 0) {
    dirs.push(path.resolve(envBin.trim()));
  }

  // 3. System immutable container directory (/opt/secureship/bin)
  const systemDir = '/opt/secureship/bin';
  try {
    if (fs.existsSync(systemDir)) {
      dirs.push(systemDir);
    }
  } catch {
    // Ignore permissions check errors
  }

  // 4. User default home bin directory (<SECURESHIP_HOME>/bin)
  const userBin = path.join(resolveSecureshipHome(), 'bin');
  dirs.push(userBin);

  // De-duplicate while preserving precedence order
  const uniqueDirs = Array.from(new Set(dirs));

  // If a target directory is provided, apply planted-binary defense
  if (options.targetDir) {
    for (const d of uniqueDirs) {
      assertNotInsideTarget(d, options.targetDir);
    }
  }

  return uniqueDirs;
}

/**
 * Returns the primary default directory where new tools should be installed.
 * Honors SECURESHIP_BIN_DIR, falling back to <SECURESHIP_HOME>/bin.
 */
export function getDefaultToolDir(): string {
  if (process.env.SECURESHIP_BIN_DIR?.trim()) {
    return path.resolve(process.env.SECURESHIP_BIN_DIR.trim());
  }
  return path.join(resolveSecureshipHome(), 'bin');
}

/**
 * Returns the offline vulnerability database directory.
 * Honors SECURESHIP_DB_DIR environment variable, falling back to <SECURESHIP_HOME>/db.
 */
export function resolveDbDir(explicitDir?: string): string {
  if (explicitDir && explicitDir.trim().length > 0) {
    return path.resolve(explicitDir.trim());
  }
  const envDb = process.env.SECURESHIP_DB_DIR;
  if (envDb && envDb.trim().length > 0) {
    return path.resolve(envDb.trim());
  }
  return path.join(resolveSecureshipHome(), 'db');
}

/**
 * Detects whether execution is running inside a Docker or container runtime.
 */
export function isContainerEnvironment(): boolean {
  if (process.env.SECURESHIP_CONTAINER === '1' || process.env.CONTAINER === 'true') {
    return true;
  }
  try {
    if (fs.existsSync('/.dockerenv')) {
      return true;
    }
  } catch {
    // Ignore
  }
  try {
    if (fs.existsSync('/proc/1/cgroup')) {
      const cgroup = fs.readFileSync('/proc/1/cgroup', 'utf-8');
      if (
        cgroup.includes('docker') ||
        cgroup.includes('containerd') ||
        cgroup.includes('kubepods')
      ) {
        return true;
      }
    }
  } catch {
    // Ignore
  }
  return false;
}

/**
 * Checks if a directory is writable by the current process.
 * If non-writable, returns an actionable error message explaining how to fix it.
 */
export function checkDirWritable(dirPath: string): { writable: boolean; error?: string } {
  try {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
    fs.accessSync(dirPath, fs.constants.W_OK);
    return { writable: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const actionable =
      `Directory '${dirPath}' is not writable (${msg}). ` +
      `Fix: Ensure the directory is owned by your user (UID ${process.getuid ? process.getuid() : 'current'}), ` +
      `adjust mount permissions (e.g. docker run --user 10001:10001), ` +
      `or specify an alternate writable directory via SECURESHIP_HOME / SECURESHIP_BIN_DIR.`;
    return { writable: false, error: actionable };
  }
}

/**
 * Security barrier preventing planted-binary attacks:
 * Asserts that candidate path (binary or directory) does NOT reside inside the targetDir repository.
 */
export function assertNotInsideTarget(candidatePath: string, targetDir: string): void {
  try {
    const resolvedTarget = path.resolve(targetDir);
    const resolvedCandidate = path.resolve(candidatePath);

    let realTarget = resolvedTarget;
    try {
      if (fs.existsSync(resolvedTarget)) {
        realTarget = fs.realpathSync(resolvedTarget);
      }
    } catch {
      // Use resolvedTarget
    }

    let realCandidate = resolvedCandidate;
    try {
      if (fs.existsSync(resolvedCandidate)) {
        realCandidate = fs.realpathSync(resolvedCandidate);
      }
    } catch {
      // Use resolvedCandidate
    }

    const relative = path.relative(realTarget, realCandidate);
    // If relative path does not start with '..' and is not absolute, it is inside realTarget!
    if (
      relative === '' ||
      (!relative.startsWith('..') && !path.isAbsolute(relative) && !relative.startsWith('\\'))
    ) {
      throw new Error(
        `Security violation: Scanner binary '${candidatePath}' resides inside target directory '${targetDir}'. Execution blocked to prevent planted-binary attack.`
      );
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.message.includes('Security violation')) {
      throw err;
    }
  }
}
