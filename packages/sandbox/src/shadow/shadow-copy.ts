import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

export interface ShadowCopyOptions {
  sourceDir: string;
  customExcludes?: string[];
  maxFileSizeBytes?: number;
}

export class ShadowCopy {
  public static readonly DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

  public static readonly SENSITIVE_EXCLUDE_PATTERNS = [
    /^\.env/i,
    /(^|\/)\.env/i,
    /\.pem$/i,
    /\.key$/i,
    /(^|\/)id_rsa/i,
    /(^|\/)id_ed25519/i,
    /(^|\/)id_ecdsa/i,
    /(^|\/)id_dsa/i,
    /(^|\/)credentials/i,
    /(^|\/)\.aws\//i,
    /(^|\/)\.ssh\//i,
    /^\.npmrc$/i,
    /^\.pypirc$/i,
    /^\.netrc$/i,
    /terraform\.tfstate/i,
    /\.pfx$/i,
    /\.p12$/i,
    /\.kdbx$/i,
    /\.keystore$/i,
  ];

  public static readonly DIRECTORY_EXCLUDES = new Set([
    '.git',
    'node_modules',
    'venv',
    '.venv',
    'env',
    '.env_dir',
    'dist',
    'build',
    'out',
    'coverage',
    '.turbo',
    '.next',
    '.nuxt',
    '.secureship',
  ]);

  public readonly shadowDir: string;
  public readonly sourceDir: string;
  public readonly sourceManifest: Map<string, string> = new Map();
  private cleanedUp = false;
  private readonly exitHandler: () => void;

  private constructor(sourceDir: string, shadowDir: string) {
    this.sourceDir = path.resolve(sourceDir);
    this.shadowDir = path.resolve(shadowDir);

    this.exitHandler = () => {
      this.cleanup();
    };

    process.once('exit', this.exitHandler);
    process.once('SIGINT', this.exitHandler);
    process.once('SIGTERM', this.exitHandler);
  }

  /**
   * Creates a filtered shadow copy of sourceDir outside the repository.
   * Strictly verifies directory boundaries to prevent recursive loops.
   */
  public static create(options: ShadowCopyOptions): ShadowCopy {
    const sourceResolved = path.resolve(options.sourceDir);
    if (!fs.existsSync(sourceResolved) || !fs.statSync(sourceResolved).isDirectory()) {
      throw new Error(`Source directory does not exist or is not a directory: '${sourceResolved}'`);
    }

    const tmpBase = os.tmpdir();
    const shadowPath = fs.mkdtempSync(path.join(tmpBase, 'secureship-shadow-'));

    // Guard: shadow must not be inside source, and source must not be inside shadow
    const relFromSource = path.relative(sourceResolved, shadowPath);
    if (!relFromSource.startsWith('..') && !path.isAbsolute(relFromSource)) {
      throw new Error(`Security Error: Shadow copy destination is inside source repository`);
    }

    const relFromShadow = path.relative(shadowPath, sourceResolved);
    if (!relFromShadow.startsWith('..') && !path.isAbsolute(relFromShadow)) {
      throw new Error(`Security Error: Source repository is inside shadow copy destination`);
    }

    const instance = new ShadowCopy(sourceResolved, shadowPath);
    try {
      instance.copyFiltered(sourceResolved, shadowPath, options);
    } catch (err) {
      instance.cleanup();
      throw err;
    }

    return instance;
  }

  private copyFiltered(
    currentSourceDir: string,
    currentDestDir: string,
    options: ShadowCopyOptions
  ): void {
    const entries = fs.readdirSync(currentSourceDir, { withFileTypes: true });
    const maxFileSize = options.maxFileSizeBytes ?? ShadowCopy.DEFAULT_MAX_FILE_SIZE_BYTES;

    for (const entry of entries) {
      const srcPath = path.join(currentSourceDir, entry.name);
      const destPath = path.join(currentDestDir, entry.name);
      const relPosix = path.relative(this.sourceDir, srcPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        if (ShadowCopy.DIRECTORY_EXCLUDES.has(entry.name)) {
          continue;
        }
        if (ShadowCopy.SENSITIVE_EXCLUDE_PATTERNS.some((pat) => pat.test(relPosix + '/'))) {
          continue;
        }

        fs.mkdirSync(destPath, { recursive: true, mode: 0o700 });
        this.copyFiltered(srcPath, destPath, options);
      } else if (entry.isSymbolicLink()) {
        try {
          const target = fs.readlinkSync(srcPath);
          const resolvedTarget = path.resolve(currentSourceDir, target);
          const relToRoot = path.relative(this.sourceDir, resolvedTarget);
          if (relToRoot.startsWith('..') || path.isAbsolute(relToRoot)) {
            // Symlink points outside repo root - skip for security
            continue;
          }
          // Copy target file content instead of symlink for strict container isolation
          if (fs.existsSync(resolvedTarget) && fs.statSync(resolvedTarget).isFile()) {
            this.copyFileWithManifest(resolvedTarget, destPath, relPosix, maxFileSize);
          }
        } catch {
          // Skip broken symlinks
          continue;
        }
      } else if (entry.isFile()) {
        if (ShadowCopy.SENSITIVE_EXCLUDE_PATTERNS.some((pat) => pat.test(relPosix))) {
          continue;
        }

        try {
          const stat = fs.statSync(srcPath);
          if (stat.size > maxFileSize) {
            // Exceeds 5MB cap - skip
            continue;
          }

          this.copyFileWithManifest(srcPath, destPath, relPosix, maxFileSize);
        } catch {
          // File unreadable or disappeared
          continue;
        }
      }
    }
  }

  private copyFileWithManifest(
    srcPath: string,
    destPath: string,
    relPosix: string,
    _maxFileSize: number
  ): void {
    const content = fs.readFileSync(srcPath);
    const hash = crypto.createHash('sha256').update(content).digest('hex');

    this.sourceManifest.set(relPosix, hash);

    const destDir = path.dirname(destPath);
    if (!fs.existsSync(destDir)) {
      fs.mkdirSync(destDir, { recursive: true });
    }

    fs.writeFileSync(destPath, content);
  }

  /**
   * Verifies that the original source repository working tree is completely unchanged.
   * Compares the current SHA-256 of every file recorded in sourceManifest.
   * Throws an Error if any file was modified, deleted, or altered.
   */
  public verifyOriginalUnchanged(): boolean {
    for (const [relPath, expectedHash] of this.sourceManifest.entries()) {
      const fullSrcPath = path.join(this.sourceDir, relPath);
      if (!fs.existsSync(fullSrcPath)) {
        throw new Error(
          `Integrity Violation: Source file '${relPath}' was deleted from original repository tree!`
        );
      }

      const currentContent = fs.readFileSync(fullSrcPath);
      const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');

      if (currentHash !== expectedHash) {
        throw new Error(
          `Integrity Violation: Source file '${relPath}' was modified in original repository tree! (expected ${expectedHash}, got ${currentHash})`
        );
      }
    }

    return true;
  }

  /**
   * Cleans up the shadow copy directory and unregisters process hooks.
   */
  public cleanup(): void {
    if (this.cleanedUp) return;
    this.cleanedUp = true;

    try {
      process.removeListener('exit', this.exitHandler);
      process.removeListener('SIGINT', this.exitHandler);
      process.removeListener('SIGTERM', this.exitHandler);
    } catch {
      // Ignore
    }

    if (fs.existsSync(this.shadowDir)) {
      // Retry loop for Windows file lock delays
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          fs.rmSync(this.shadowDir, { recursive: true, force: true, maxRetries: 3 });
          break;
        } catch {
          // Small synchronous pause before retry
          const start = Date.now();
          while (Date.now() - start < 50) {}
        }
      }
    }
  }
}
