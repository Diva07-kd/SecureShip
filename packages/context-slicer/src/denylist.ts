import fs from 'node:fs';
import path from 'node:path';

export class SlicerDenylist {
  private static readonly SENSITIVE_FILENAME_PATTERNS: RegExp[] = [
    /^\.env.*$/i,
    /\.(pem|key|pkcs12|p12|pfx|kdbx|crt|der|jks|keystore)$/i,
    /^id_rsa.*$/i,
    /^id_(dsa|ecdsa|ed25519).*$/i,
    /^(credentials|secrets?).*$/i,
    /^\.(npmrc|pypirc|netrc)$/i,
    /(^|\.)terraform\.tfstate.*$/i,
    /\.tfstate.*$/i,
  ];

  private static readonly SENSITIVE_DIR_SEGMENTS = new Set([
    '.git',
    '.ssh',
    '.aws',
    '.azure',
    '.gcp',
    '.kube',
    '.secureship',
  ]);

  /**
   * Checks if a relative or absolute path matches sensitive denylist rules.
   */
  public static isDenylisted(filePath: string): boolean {
    if (!filePath) return false;
    const normalized = filePath.replace(/\\/g, '/');
    const segments = normalized.split('/').filter(Boolean);

    for (const segment of segments) {
      if (SlicerDenylist.SENSITIVE_DIR_SEGMENTS.has(segment.toLowerCase())) {
        return true;
      }
      for (const pattern of SlicerDenylist.SENSITIVE_FILENAME_PATTERNS) {
        if (pattern.test(segment)) {
          return true;
        }
      }
    }

    const basename = path.basename(filePath);
    for (const pattern of SlicerDenylist.SENSITIVE_FILENAME_PATTERNS) {
      if (pattern.test(basename)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Verifies that the path (including resolved symlinks) is strictly confined
   * within the workspace root directory.
   */
  public static isWithinRoot(workspaceRoot: string, targetPath: string): boolean {
    try {
      const realRoot = fs.existsSync(workspaceRoot)
        ? fs.realpathSync(path.resolve(workspaceRoot))
        : path.resolve(workspaceRoot);

      const resolvedTarget = path.isAbsolute(targetPath)
        ? path.resolve(targetPath)
        : path.resolve(workspaceRoot, targetPath);

      // Resolve real path of target if it exists, or traverse up to nearest existing parent
      let checkPath = resolvedTarget;
      while (!fs.existsSync(checkPath) && path.dirname(checkPath) !== checkPath) {
        checkPath = path.dirname(checkPath);
      }

      const realTarget = fs.existsSync(checkPath)
        ? fs.realpathSync(checkPath)
        : path.resolve(checkPath);

      const normalizedRoot = realRoot.replace(/\\/g, '/').toLowerCase();
      const normalizedTarget = realTarget.replace(/\\/g, '/').toLowerCase();

      return (
        normalizedTarget === normalizedRoot ||
        normalizedTarget.startsWith(
          normalizedRoot.endsWith('/') ? normalizedRoot : `${normalizedRoot}/`
        )
      );
    } catch {
      return false;
    }
  }

  /**
   * Converts a path to a root-relative POSIX path (no absolute paths or user home info).
   */
  public static toRootRelativePosix(workspaceRoot: string, targetPath: string): string {
    const absRoot = path.resolve(workspaceRoot).replace(/\\/g, '/');
    let normalized = path.isAbsolute(targetPath)
      ? path.resolve(targetPath).replace(/\\/g, '/')
      : path.resolve(workspaceRoot, targetPath).replace(/\\/g, '/');

    if (normalized.startsWith(absRoot)) {
      normalized = normalized.slice(absRoot.length);
    }

    // Strip leading slashes
    normalized = normalized.replace(/^\/+/, '');
    return normalized || '.';
  }

  /**
   * Jails a target path inside the workspace root (A11).
   * Returns root-relative POSIX path if within root, or null if outside.
   */
  public static jailPath(workspaceRoot: string, targetPath: string): string | null {
    if (!SlicerDenylist.isWithinRoot(workspaceRoot, targetPath)) {
      return null;
    }
    return SlicerDenylist.toRootRelativePosix(workspaceRoot, targetPath);
  }
}
