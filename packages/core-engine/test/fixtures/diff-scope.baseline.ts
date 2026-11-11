import path from 'node:path';
import { existsSync } from 'node:fs';
import { SafeProcessRunner } from '../../src/sandbox/safe-process-runner.js';
import { FindingCorrelator } from '../../src/normalizer/finding-correlator.js';
import { isContainerEnvironment } from '../../src/paths/index.js';
import type { NormalizedFinding } from '@secureship/contracts';

export interface DiffScopeOptions {
  diffRef?: string;
  staged?: boolean;
  diffLines?: boolean;
}

export interface LineRange {
  startLine: number;
  endLine: number;
}

export interface DiffScopeResult {
  isDiffMode: boolean;
  changedFiles: Set<string>;
  fileLineRanges: Map<string, LineRange[]>;
}

export class DiffScope {
  /**
   * Strictly validates a git reference to prevent CLI option injection.
   * Throws if the ref starts with a dash or contains dangerous shell metacharacters.
   */
  public static validateRef(ref?: string): void {
    if (!ref) return;

    if (ref.startsWith('-')) {
      throw new Error(
        `Invalid git reference '${ref}': references starting with '-' are disallowed to prevent option injection.`
      );
    }

    // Reject control characters, NUL bytes, whitespace, and dangerous shell metacharacters
    if (/[\x00-\x1F\x7F\s;&|`$<>(){}"'\\]/.test(ref)) {
      throw new Error(
        `Invalid git reference '${ref}': reference contains invalid or disallowed characters.`
      );
    }
  }

  /**
   * Resolves modified files and changed line ranges using git via SafeProcessRunner.
   */
  public static async computeDiffScope(
    targetDir: string,
    options: DiffScopeOptions = {}
  ): Promise<DiffScopeResult> {
    const isDiffMode = Boolean(options.diffRef || options.staged);
    if (!isDiffMode) {
      return {
        isDiffMode: false,
        changedFiles: new Set<string>(),
        fileLineRanges: new Map<string, LineRange[]>(),
      };
    }

    if (options.diffRef) {
      DiffScope.validateRef(options.diffRef);
    }

    // Verify git repository exists
    const gitDir = path.join(targetDir, '.git');
    if (!existsSync(gitDir)) {
      throw new Error(
        `Directory '${targetDir}' is not a git repository. Incremental scan requires an initialized git repository.`
      );
    }

    // Container awareness (D6): if running in container, configure safe.directory for target only
    const resolvedTarget = path.resolve(targetDir);
    const gitContainerArgs = isContainerEnvironment()
      ? ['-c', `safe.directory=${resolvedTarget}`]
      : [];

    if (options.diffRef) {
      const revParseRun = await SafeProcessRunner.run(
        'git',
        [...gitContainerArgs, 'rev-parse', '--verify', '--end-of-options', options.diffRef],
        {
          cwd: targetDir,
          timeoutMs: 5_000,
        }
      );

      if (revParseRun.exitCode !== 0) {
        throw new Error(
          `Unknown git ref '${options.diffRef}' (the repository may have too few commits)`
        );
      }
    }

    const changedFiles = new Set<string>();
    const fileLineRanges = new Map<string, LineRange[]>();

    // 1. Get changed files using git diff -z --name-status
    const diffArgs = ['diff', '--name-status', '-z'];
    if (options.staged) {
      diffArgs.push('--cached');
    }
    if (options.diffRef) {
      diffArgs.push('--end-of-options', options.diffRef, '--');
    }

    const diffRun = await SafeProcessRunner.run('git', [...gitContainerArgs, ...diffArgs], {
      cwd: targetDir,
      timeoutMs: 15_000,
    });

    if (diffRun.exitCode !== 0) {
      throw new Error(
        `git diff failed with exit code ${diffRun.exitCode}: ${diffRun.stderr.trim()}`
      );
    }

    // Parse -z output: records separated by NUL \0
    const rawParts = diffRun.stdout.split('\0').filter(Boolean);
    let i = 0;
    while (i < rawParts.length) {
      const status = rawParts[i] ?? '';
      if (status.startsWith('R') || status.startsWith('C')) {
        // Renamed / Copied: format is Status \0 OldPath \0 NewPath
        const _oldPath = rawParts[i + 1];
        const newPath = rawParts[i + 2];
        if (newPath) {
          changedFiles.add(FindingCorrelator.toPosix(newPath));
        }
        i += 3;
      } else {
        // Normal change: Status \0 Path
        const filePath = rawParts[i + 1];
        if (filePath && status !== 'D') {
          // Deleted files don't need finding scans
          changedFiles.add(FindingCorrelator.toPosix(filePath));
        }
        i += 2;
      }
    }

    // 2. Also check untracked files if scanning working tree (not staged-only)
    if (!options.staged) {
      const statusRun = await SafeProcessRunner.run(
        'git',
        [...gitContainerArgs, 'status', '--porcelain=v1', '-z'],
        {
          cwd: targetDir,
          timeoutMs: 15_000,
        }
      );
      if (statusRun.exitCode === 0) {
        const statusParts = statusRun.stdout.split('\0').filter(Boolean);
        for (const item of statusParts) {
          if (item.startsWith('?? ')) {
            const untracked = item.slice(3).trim();
            if (untracked) {
              changedFiles.add(FindingCorrelator.toPosix(untracked));
            }
          }
        }
      }
    }

    // 3. If --diff-lines is requested, extract line numbers from unified diff hunks
    if (options.diffLines) {
      const hunkArgs = ['diff', '-U0'];
      if (options.staged) {
        hunkArgs.push('--cached');
      }
      if (options.diffRef) {
        hunkArgs.push('--end-of-options', options.diffRef, '--');
      }

      const hunkRun = await SafeProcessRunner.run('git', [...gitContainerArgs, ...hunkArgs], {
        cwd: targetDir,
        timeoutMs: 20_000,
      });

      if (hunkRun.exitCode === 0) {
        DiffScope.parseHunkRanges(hunkRun.stdout, fileLineRanges);
      }
    }

    return {
      isDiffMode: true,
      changedFiles,
      fileLineRanges,
    };
  }

  /**
   * Parses git unified diff hunk headers: @@ -oldStart,oldLen +newStart,newLen @@
   */
  public static parseHunkRanges(diffOutput: string, resultMap: Map<string, LineRange[]>): void {
    const lines = diffOutput.split('\n');
    let currentFile: string | null = null;

    for (const line of lines) {
      if (line.startsWith('+++ b/')) {
        currentFile = FindingCorrelator.toPosix(line.slice(6).trim());
        if (!resultMap.has(currentFile)) {
          resultMap.set(currentFile, []);
        }
      } else if (line.startsWith('@@ ') && currentFile) {
        // Example: @@ -10,0 +15,5 @@ or @@ -1 +1 @@
        const match = line.match(/@@\s+-[0-9]+(?:,[0-9]+)?\s+\+([0-9]+)(?:,([0-9]+))?\s+@@/);
        if (match && match[1]) {
          const startLine = parseInt(match[1], 10);
          const count = match[2] ? parseInt(match[2], 10) : 1;
          const endLine = count === 0 ? startLine : startLine + count - 1;

          const ranges = resultMap.get(currentFile) ?? [];
          ranges.push({ startLine, endLine });
          resultMap.set(currentFile, ranges);
        }
      }
    }
  }

  /**
   * Tests whether a finding is within the diff scope.
   * - Full scan mode: all findings are in scope.
   * - Diff mode:
   *   - SECRET category checks whole file presence in changedFiles.
   *   - If diffLines active and line ranges available: checks if finding lines intersect modified hunks.
   *   - Otherwise: checks if file is in changedFiles.
   */
  public static isFindingInScope(
    finding: NormalizedFinding,
    scope: DiffScopeResult,
    diffLinesMode = false
  ): boolean {
    if (!scope.isDiffMode) {
      return true;
    }

    const posixPath = FindingCorrelator.toPosix(finding.location.filePath);
    if (!scope.changedFiles.has(posixPath)) {
      return false;
    }

    // Secrets in diff mode always inspect whole changed files
    if (finding.category === 'SECRET' || !diffLinesMode) {
      return true;
    }

    // Check line intersection for SAST / SCA / IAC when --diff-lines is set
    const ranges = scope.fileLineRanges.get(posixPath);
    if (!ranges || ranges.length === 0) {
      return true;
    }

    const fStart = finding.location.startLine;
    const fEnd = finding.location.endLine;

    // Check if finding range intersects any changed hunk range
    for (const r of ranges) {
      if (fStart <= r.endLine && fEnd >= r.startLine) {
        return true;
      }
    }

    return false;
  }
}
