import path from 'node:path';
import { existsSync, statSync } from 'node:fs';
import { SafeProcessRunner, type ProcessRunResult } from '../sandbox/safe-process-runner.js';
import { FindingCorrelator } from '../normalizer/finding-correlator.js';
import { isContainerEnvironment } from '../paths/index.js';
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
  repoRoot?: string;
  repoPrefix?: string;
  targetRelativeFiles?: string[];
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
   * Helper that builds the git argv array for diff operations.
   * Ensures deterministic flags, safe quoting, and proper option ordering:
   * - -c core.quotePath=false: prevents C-style octal quoting of non-ASCII characters in filenames.
   * - --relative: guarantees git diff output is relative to targetDir (cwd) and omits sibling changes.
   * - --: separates flags/options and revisions from pathspecs.
   * - .: limits the tree traversal to cwd, optimizing monorepo performance and guarding directory boundaries.
   * - --no-color: strips ANSI color sequences that break diff header parsing.
   * - --no-ext-diff: disables external diff tools configured by user/system gitconfig.
   * - --no-textconv: disables custom text conversion filters.
   * - --src-prefix=a/ --dst-prefix=b/: forces canonical unified diff prefixes regardless of diff.noprefix or diff.mnemonicPrefix.
   * - ls-files --others --exclude-standard -z: lists untracked files relative to cwd, expands directories, and avoids git status index locks.
   */
  public static buildGitArgs(
    kind: 'changedFiles' | 'untracked' | 'hunks',
    options: DiffScopeOptions = {},
    gitContainerArgs: string[] = []
  ): string[] {
    if (kind === 'untracked') {
      return [...gitContainerArgs, 'ls-files', '--others', '--exclude-standard', '-z'];
    }

    if (kind === 'changedFiles') {
      const args: string[] = [
        ...gitContainerArgs,
        '-c',
        'core.quotePath=false',
        'diff',
        '--name-status',
        '-z',
        '--relative',
      ];
      if (options.staged) {
        args.push('--cached');
      }
      if (options.diffRef) {
        args.push('--end-of-options', options.diffRef);
      }
      args.push('--', '.');
      return args;
    }

    // kind === 'hunks'
    const args: string[] = [
      ...gitContainerArgs,
      '-c',
      'core.quotePath=false',
      'diff',
      '-U0',
      '--relative',
      '--no-color',
      '--no-ext-diff',
      '--no-textconv',
      '--src-prefix=a/',
      '--dst-prefix=b/',
    ];
    if (options.staged) {
      args.push('--cached');
    }
    if (options.diffRef) {
      args.push('--end-of-options', options.diffRef);
    }
    args.push('--', '.');
    return args;
  }

  /**
   * Resolves the enclosing git repository root and relative prefix for targetDir.
   *
   * Container Defense (DEV-1.e):
   * When running in container environments (SECURESHIP_CONTAINER=1), git safe.directory
   * is strictly scoped to the resolved target directory itself (`-c safe.directory=${resolvedTarget}`).
   * Git ownership verification does not grant trust to parent repositories when safe.directory
   * specifies only a subdirectory. If dubious ownership is detected for an ancestor repository,
   * this method fails closed. We never auto-trust ancestor directories, never set safe.directory=*,
   * and never widen safe.directory, ensuring planted ancestor .git directories or malicious host mounts
   * cannot achieve code execution.
   */
  private static async resolveRepository(
    targetDir: string,
    resolvedTarget: string,
    gitContainerArgs: string[]
  ): Promise<{ repoRoot: string; repoPrefix: string }> {
    // a. Pre-check: if resolve(targetDir) does not exist or is not a directory, throw I2 error
    try {
      const st = statSync(resolvedTarget);
      if (!st.isDirectory()) {
        throw new Error(
          `Directory '${targetDir}' is not a git repository. Incremental scan requires an initialized git repository.`
        );
      }
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        err.message.includes('Incremental scan requires an initialized git repository.')
      ) {
        throw err;
      }
      throw new Error(
        `Directory '${targetDir}' is not a git repository. Incremental scan requires an initialized git repository.`
      );
    }

    // c. Run git rev-parse with cwd = resolvedTarget
    let runResult: ProcessRunResult;
    try {
      runResult = await SafeProcessRunner.run(
        'git',
        [
          ...gitContainerArgs,
          'rev-parse',
          '--is-inside-work-tree',
          '--show-toplevel',
          '--show-prefix',
        ],
        {
          cwd: resolvedTarget,
          timeoutMs: 5_000,
        }
      );
    } catch (err: unknown) {
      const rawMsg = err instanceof Error ? err.message : String(err);
      const firstLine = rawMsg.split(/\r?\n/)[0]?.trim().slice(0, 200) || 'Unknown error';
      throw new Error(`Unable to run git for '${targetDir}': ${firstLine}`);
    }

    if (runResult.timedOut) {
      throw new Error(`Unable to run git for '${targetDir}': git rev-parse timed out`);
    }

    // d. Classification
    if (runResult.exitCode === 0) {
      const lines = runResult.stdout.split(/\r?\n/);
      while (lines.length > 0 && lines[lines.length - 1] === '') {
        lines.pop();
      }

      if (lines[0] === 'false') {
        throw new Error(
          `Directory '${targetDir}' is not a git repository. Incremental scan requires an initialized git repository.`
        );
      }

      if (lines[0] !== 'true' || !lines[1] || lines[1].trim() === '' || lines.length > 3) {
        throw new Error(
          `Unexpected output from git while resolving the repository for '${targetDir}'`
        );
      }

      const toplevel = lines[1].trim();
      const rawPrefix = lines[2] ?? '';
      const repoPrefix = rawPrefix.endsWith('/') ? rawPrefix.slice(0, -1) : rawPrefix;
      const repoRoot = path.resolve(toplevel);
      return { repoRoot, repoPrefix };
    }

    // exitCode !== 0: ascend from resolvedTarget through ancestors checking for .git (file or directory)
    let hasGitAncestor = false;
    let current = resolvedTarget;
    while (true) {
      if (existsSync(path.join(current, '.git'))) {
        hasGitAncestor = true;
        break;
      }
      const parent = path.dirname(current);
      if (parent === current) {
        break;
      }
      current = parent;
    }

    if (!hasGitAncestor) {
      throw new Error(
        `Directory '${targetDir}' is not a git repository. Incremental scan requires an initialized git repository.`
      );
    }

    // Ancestor .git exists, but rev-parse failed (e.g. dubious ownership, inside .git/, corrupt repo)
    const firstStderrLine = runResult.stderr
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l.length > 0);

    const detail = firstStderrLine
      ? firstStderrLine.slice(0, 200)
      : `git rev-parse exited with code ${runResult.exitCode ?? 'unknown'}`;

    throw new Error(`Unable to resolve the git repository for '${targetDir}': ${detail}`);
  }

  /**
   * Resolves modified files and changed line ranges using git via SafeProcessRunner.
   *
   * Dual Namespaces (DEV-3, DEV-5):
   * changedFiles and fileLineRanges register both:
   * (a) target-relative POSIX path (e.g. 'src/index.ts'), consumed by scanner finding locations;
   * (b) repo-relative POSIX path (e.g. 'packages/core-engine/src/index.ts') when targetDir is a subdirectory.
   * targetRelativeFiles provides sorted, deduplicated target-relative POSIX paths only, ensuring
   * external scanners (e.g. opengrep --include) receive clean paths without root-relative duplicates.
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

    const resolvedTarget = path.resolve(targetDir);
    const gitContainerArgs = isContainerEnvironment()
      ? ['-c', `safe.directory=${resolvedTarget}`]
      : [];

    // Discover repository root and subdirectory prefix
    const { repoRoot, repoPrefix } = await DiffScope.resolveRepository(
      targetDir,
      resolvedTarget,
      gitContainerArgs
    );

    if (options.diffRef) {
      const revParseRun = await SafeProcessRunner.run(
        'git',
        [...gitContainerArgs, 'rev-parse', '--verify', '--end-of-options', options.diffRef],
        {
          cwd: resolvedTarget,
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
    const targetRelativeSet = new Set<string>();
    const fileLineRanges = new Map<string, LineRange[]>();

    const registerPath = (rawPath: string) => {
      const targetRel = FindingCorrelator.toPosix(rawPath);
      // Defence in depth: skip any entry whose target-relative form starts with '../', is '.', '..', or is absolute
      if (
        !targetRel ||
        targetRel === '.' ||
        targetRel === '..' ||
        targetRel.startsWith('../') ||
        path.isAbsolute(targetRel) ||
        targetRel.startsWith('/') ||
        /^[a-zA-Z]:/.test(targetRel)
      ) {
        return;
      }
      changedFiles.add(targetRel);
      targetRelativeSet.add(targetRel);
      if (repoPrefix !== '') {
        changedFiles.add(`${repoPrefix}/${targetRel}`);
      }
    };

    // 1. Get changed files using git diff -z --name-status --relative -- .
    const diffArgs = DiffScope.buildGitArgs('changedFiles', options, gitContainerArgs);
    const diffRun = await SafeProcessRunner.run('git', diffArgs, {
      cwd: resolvedTarget,
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
          registerPath(newPath);
        }
        i += 3;
      } else {
        // Normal change: Status \0 Path
        const filePath = rawParts[i + 1];
        if (filePath && status !== 'D') {
          // Deleted files don't need finding scans
          registerPath(filePath);
        }
        i += 2;
      }
    }

    // 2. Also check untracked files if scanning working tree (not staged-only)
    if (!options.staged) {
      const untrackedArgs = DiffScope.buildGitArgs('untracked', options, gitContainerArgs);
      const untrackedRun = await SafeProcessRunner.run('git', untrackedArgs, {
        cwd: resolvedTarget,
        timeoutMs: 15_000,
      });
      if (untrackedRun.exitCode === 0) {
        const untrackedParts = untrackedRun.stdout.split('\0').filter(Boolean);
        for (const item of untrackedParts) {
          if (item.endsWith('/')) {
            // Skip directory entries / nested repositories
            continue;
          }
          registerPath(item);
        }
      }
    }

    // 3. If --diff-lines is requested, extract line numbers from unified diff hunks
    if (options.diffLines) {
      const hunkArgs = DiffScope.buildGitArgs('hunks', options, gitContainerArgs);
      const hunkRun = await SafeProcessRunner.run('git', hunkArgs, {
        cwd: resolvedTarget,
        timeoutMs: 20_000,
      });

      if (hunkRun.exitCode === 0) {
        const tempMap = new Map<string, LineRange[]>();
        DiffScope.parseHunkRanges(hunkRun.stdout, tempMap);

        for (const [rawFile, ranges] of tempMap.entries()) {
          const targetRel = FindingCorrelator.toPosix(rawFile);
          if (
            !targetRel ||
            targetRel === '.' ||
            targetRel === '..' ||
            targetRel.startsWith('../') ||
            path.isAbsolute(targetRel) ||
            targetRel.startsWith('/') ||
            /^[a-zA-Z]:/.test(targetRel)
          ) {
            continue;
          }
          const targetRanges: LineRange[] = ranges.map((r) => ({ ...r }));
          fileLineRanges.set(targetRel, targetRanges);

          if (repoPrefix !== '') {
            const repoRanges: LineRange[] = ranges.map((r) => ({ ...r }));
            fileLineRanges.set(`${repoPrefix}/${targetRel}`, repoRanges);
          }
        }
      }
    }

    const targetRelativeFiles = Array.from(targetRelativeSet).sort();

    return {
      isDiffMode: true,
      changedFiles,
      fileLineRanges,
      repoRoot,
      repoPrefix,
      targetRelativeFiles,
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
