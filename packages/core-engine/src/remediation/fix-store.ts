import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { resolveSecureshipHome } from '../paths/index.js';
import { execFileSync } from 'node:child_process';
import {
  FixReportSchema,
  type FixReport,
  ScaFixReportSchema,
  type ScaFixReport,
} from '@secureship/contracts';
import { DiffParser, PatchApplier } from '@secureship/patch-engine';
import { VerificationLadder } from './verification-ladder.js';
import { ScaVerificationLadder } from './sca-verification-ladder.js';

export interface ApplyFixOptions {
  allowNonGit?: boolean;
  allowDirty?: boolean;
}

export interface ApplyFixResult {
  success: boolean;
  exitCode: number;
  error?: string;
  appliedFiles?: string[];
}

export class FixStore {
  private readonly baseDir: string;

  constructor(explicitBaseDir?: string) {
    this.baseDir = explicitBaseDir ?? FixStore.resolveDefaultBaseDir();
  }

  public static resolveDefaultBaseDir(): string {
    return path.join(resolveSecureshipHome(), 'fixes');
  }

  public static computeRepoHash(repoPath: string): string {
    const canonical = path.resolve(repoPath).replace(/\\/g, '/');
    return crypto.createHash('sha256').update(canonical).digest('hex');
  }

  public static generateFixId(fingerprint: string): string {
    const shortFp = fingerprint.slice(0, 8);
    const rand = crypto.randomBytes(4).toString('hex');
    return `fix-${shortFp}-${rand}`;
  }

  /**
   * Saves a FixReport and patch diff to the external fix store.
   */
  public async saveFix(
    repoPath: string,
    report: FixReport | ScaFixReport,
    diff: string,
    fixId?: string
  ): Promise<string> {
    const repoHash = FixStore.computeRepoHash(repoPath);
    const id = fixId ?? FixStore.generateFixId(report.findingRef.fingerprint);
    const targetDir = path.join(this.baseDir, repoHash, id);

    fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });

    const reportPath = path.join(targetDir, 'report.json');
    const diffPath = path.join(targetDir, 'patch.diff');

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
    fs.writeFileSync(diffPath, diff, {
      encoding: 'utf8',
      mode: 0o600,
    });

    return id;
  }

  /**
   * Retrieves a fix by ID, strictly verifying its HMAC signature.
   */
  public async getFix(
    repoPath: string,
    fixId: string
  ): Promise<{ report: FixReport | ScaFixReport; diff: string; validSig: boolean } | null> {
    const repoHash = FixStore.computeRepoHash(repoPath);
    const targetDir = path.join(this.baseDir, repoHash, fixId);

    const reportPath = path.join(targetDir, 'report.json');
    const diffPath = path.join(targetDir, 'patch.diff');

    if (!fs.existsSync(reportPath) || !fs.existsSync(diffPath)) {
      return null;
    }

    try {
      const reportJson = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
      const isSca = reportJson.schemaVersion === '1.1';
      const report = isSca
        ? ScaFixReportSchema.parse(reportJson)
        : FixReportSchema.parse(reportJson);
      const diff = fs.readFileSync(diffPath, 'utf8');

      // Verify HMAC signature
      const validSig = isSca
        ? ScaVerificationLadder.verifySignature(report as ScaFixReport)
        : VerificationLadder.verifySignature(report as FixReport);

      return { report, diff, validSig };
    } catch {
      return null;
    }
  }

  /**
   * Lists all stored fixes for the given repository.
   */
  public async listFixes(repoPath: string): Promise<Array<FixReport | ScaFixReport>> {
    const repoHash = FixStore.computeRepoHash(repoPath);
    const repoDir = path.join(this.baseDir, repoHash);

    if (!fs.existsSync(repoDir)) {
      return [];
    }

    const entries = fs.readdirSync(repoDir, { withFileTypes: true });
    const reports: Array<FixReport | ScaFixReport> = [];

    for (const entry of entries) {
      if (entry.isDirectory()) {
        const item = await this.getFix(repoPath, entry.name);
        if (item && item.validSig) {
          reports.push(item.report);
        }
      }
    }

    return reports;
  }

  /**
   * Discards a stored fix directory.
   */
  public async discardFix(repoPath: string, fixId: string): Promise<boolean> {
    const repoHash = FixStore.computeRepoHash(repoPath);
    const targetDir = path.join(this.baseDir, repoHash, fixId);

    if (fs.existsSync(targetDir)) {
      fs.rmSync(targetDir, { recursive: true, force: true });
      return true;
    }

    return false;
  }

  /**
   * Atomically applies a verified fix to the user's working tree with strict integrity checks.
   */
  public async applyFix(
    repoPath: string,
    fixId: string,
    options: ApplyFixOptions = {}
  ): Promise<ApplyFixResult> {
    const { allowNonGit = false, allowDirty = false } = options;

    // 1. Retrieve fix and verify HMAC signature (Mutation 22 defense)
    const stored = await this.getFix(repoPath, fixId);
    if (!stored) {
      return {
        success: false,
        exitCode: 2,
        error: `Fix with ID '${fixId}' not found for repository.`,
      };
    }

    if (!stored.validSig) {
      return {
        success: false,
        exitCode: 2,
        error: `HMAC signature verification failed: fix bundle '${fixId}' has an invalid signature or was tampered with.`,
      };
    }

    const { report, diff } = stored;

    // 2. Base file hash verification (Mutation 23 defense)
    for (const baseFile of report.baseFiles ?? []) {
      const fullPath = path.resolve(repoPath, baseFile.path);
      if (!fs.existsSync(fullPath)) {
        return {
          success: false,
          exitCode: 2,
          error: `Base file '${baseFile.path}' does not exist on disk. Cannot apply fix.`,
        };
      }

      const currentHash = crypto
        .createHash('sha256')
        .update(fs.readFileSync(fullPath))
        .digest('hex');
      if (currentHash !== baseFile.sha256) {
        return {
          success: false,
          exitCode: 2,
          error: `Base file hash mismatch for '${baseFile.path}'. The file was modified since fix generation. Expected ${baseFile.sha256}, got ${currentHash}.`,
        };
      }
    }

    // 3. Git repository and clean tree check (Mutation 24 defense)
    let isGitRepo = false;
    try {
      const gitOut = execFileSync('git', ['rev-parse', '--is-inside-work-tree'], {
        cwd: repoPath,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      isGitRepo = gitOut.trim() === 'true';
    } catch {
      isGitRepo = false;
    }

    if (!isGitRepo) {
      if (!allowNonGit) {
        return {
          success: false,
          exitCode: 2,
          error:
            'Repository is not a Git working tree. To apply outside a Git tree, rerun with --allow-non-git.',
        };
      }
    } else {
      if (!allowDirty) {
        let statusOut = '';
        try {
          statusOut = execFileSync('git', ['status', '--porcelain'], {
            cwd: repoPath,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
          }).trim();
        } catch {
          // Ignore
        }

        if (statusOut.length > 0) {
          return {
            success: false,
            exitCode: 2,
            error:
              'Working tree contains uncommitted changes. Commit or stash them before applying, or pass --allow-dirty.',
          };
        }
      }
    }

    // 4. Parse diff and verify
    let parsedFiles;
    try {
      parsedFiles = DiffParser.parse(diff);
    } catch (err) {
      return {
        success: false,
        exitCode: 2,
        error: `Diff parse error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    // 5. Apply atomically and preserve line endings (Mutation 25, 26, 27 defense)
    // NEVER calls git commit or git branch
    const appliedFiles: string[] = [];
    try {
      for (const parsedFile of parsedFiles) {
        const fullPath = path.resolve(repoPath, parsedFile.newPath);
        const originalText = fs.readFileSync(fullPath, 'utf8');
        const patchedText = PatchApplier.apply(originalText, parsedFile);
        PatchApplier.atomicWrite(fullPath, patchedText);
        appliedFiles.push(parsedFile.newPath);
      }
    } catch (err) {
      return {
        success: false,
        exitCode: 3,
        error: `Filesystem I/O error during atomic apply: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    return {
      success: true,
      exitCode: 0,
      appliedFiles,
    };
  }
}
