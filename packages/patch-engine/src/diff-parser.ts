import type { PatchPolicyViolationCode } from '@secureship/contracts';

export class PatchPolicyViolationError extends Error {
  constructor(
    public readonly code: PatchPolicyViolationCode,
    message: string,
    public readonly file?: string,
    public readonly line?: number
  ) {
    super(message);
    this.name = 'PatchPolicyViolationError';
  }
}

export interface ParsedHunkLine {
  type: 'context' | 'added' | 'deleted';
  text: string;
}

export interface ParsedHunk {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: ParsedHunkLine[];
  noNewlineOld?: boolean;
  noNewlineNew?: boolean;
}

export interface ParsedDiffFile {
  oldPath: string;
  newPath: string;
  hunks: ParsedHunk[];
  addedLinesCount: number;
  deletedLinesCount: number;
}

export interface ParseDiffOptions {
  maxFiles?: number;
  maxChangedLines?: number;
  maxDiffBytes?: number;
}

export class DiffParser {
  /**
   * Strictly parses a unified diff according to SecureShip Gate 4 policy.
   * Rejects fuzzy diffs, mode changes, renames, binary patches, new/deleted files,
   * directory traversal, absolute paths, or hunk count discrepancies.
   */
  public static parse(rawDiff: string, options: ParseDiffOptions = {}): ParsedDiffFile[] {
    const maxFiles = options.maxFiles ?? 1;
    const maxDiffBytes = options.maxDiffBytes ?? 20_000;
    const maxChangedLines = options.maxChangedLines ?? 60;

    const diffBytes = Buffer.byteLength(rawDiff, 'utf8');
    if (diffBytes > maxDiffBytes) {
      throw new PatchPolicyViolationError(
        'TOO_MANY_LINES',
        `Diff size (${diffBytes} bytes) exceeds maximum allowed ${maxDiffBytes} bytes`
      );
    }

    if (!rawDiff || rawDiff.trim().length === 0) {
      throw new PatchPolicyViolationError('MALFORMED_DIFF', 'Diff is empty');
    }

    // Check for binary patch indicators
    if (
      rawDiff.includes('GIT binary patch') ||
      rawDiff.includes('Binary files ') ||
      rawDiff.includes('\0')
    ) {
      throw new PatchPolicyViolationError('BINARY_PATCH', 'Binary patches are not supported');
    }

    const rawLines = rawDiff.split(/\r?\n/);
    const files: ParsedDiffFile[] = [];
    let currentFile: ParsedDiffFile | null = null;
    let currentHunk: ParsedHunk | null = null;
    let expectedOldLines = 0;
    let expectedNewLines = 0;
    let actualOldLines = 0;
    let actualNewLines = 0;
    let totalChangedLines = 0;

    for (let i = 0; i < rawLines.length; i++) {
      const line = rawLines[i] ?? '';

      // Check mode changes
      if (
        line.startsWith('new file mode') ||
        line.startsWith('old mode') ||
        line.startsWith('new mode') ||
        line.startsWith('deleted file mode')
      ) {
        if (line.includes('120000')) {
          throw new PatchPolicyViolationError('SYMLINK', 'Symlink mode changes are forbidden');
        }
        throw new PatchPolicyViolationError('MODE_CHANGE', `Mode change detected: '${line}'`);
      }

      // Check rename or copy
      if (
        line.startsWith('rename from ') ||
        line.startsWith('rename to ') ||
        line.startsWith('copy from ') ||
        line.startsWith('copy to ') ||
        line.startsWith('similarity index ')
      ) {
        throw new PatchPolicyViolationError('RENAME', `File rename or copy detected: '${line}'`);
      }

      // Old file header
      if (line.startsWith('--- ')) {
        // Complete previous hunk if open
        if (currentHunk) {
          if (actualOldLines !== expectedOldLines || actualNewLines !== expectedNewLines) {
            throw new PatchPolicyViolationError(
              'MALFORMED_DIFF',
              `Hunk count mismatch at @@ -${currentHunk.oldStart},${currentHunk.oldCount} +${currentHunk.newStart},${currentHunk.newCount} @@: expected old ${expectedOldLines}/actual ${actualOldLines}, expected new ${expectedNewLines}/actual ${actualNewLines}`
            );
          }
          currentFile?.hunks.push(currentHunk);
          currentHunk = null;
        }

        const rawOldPath = line.substring(4).trim();
        if (rawOldPath === '/dev/null') {
          throw new PatchPolicyViolationError(
            'NEW_FILE',
            'New file creation is forbidden; patch must modify existing files'
          );
        }

        const cleanOld = DiffParser.cleanAndValidatePath(rawOldPath);

        // Next line MUST be +++
        const nextLine = rawLines[i + 1];
        if (!nextLine || !nextLine.startsWith('+++ ')) {
          throw new PatchPolicyViolationError(
            'MALFORMED_DIFF',
            `Expected '+++' following '---' at line ${i + 1}`
          );
        }
        i++;
        const rawNewPath = nextLine.substring(4).trim();
        if (rawNewPath === '/dev/null') {
          throw new PatchPolicyViolationError(
            'DELETE_FILE',
            'File deletion is forbidden; patches must modify code'
          );
        }

        const cleanNew = DiffParser.cleanAndValidatePath(rawNewPath);

        if (cleanOld !== cleanNew) {
          throw new PatchPolicyViolationError(
            'RENAME',
            `Mismatched old and new file paths: '${cleanOld}' vs '${cleanNew}'`
          );
        }

        currentFile = {
          oldPath: cleanOld,
          newPath: cleanNew,
          hunks: [],
          addedLinesCount: 0,
          deletedLinesCount: 0,
        };
        files.push(currentFile);

        if (files.length > maxFiles) {
          throw new PatchPolicyViolationError(
            'TOO_MANY_FILES',
            `Diff modifies ${files.length} files, exceeding limit of ${maxFiles}`
          );
        }
        continue;
      }

      // Hunk header: @@ -l,s +l,s @@
      if (line.startsWith('@@ ')) {
        if (!currentFile) {
          throw new PatchPolicyViolationError(
            'MALFORMED_DIFF',
            'Encountered hunk header before file header'
          );
        }

        // Close previous hunk
        if (currentHunk) {
          if (actualOldLines !== expectedOldLines || actualNewLines !== expectedNewLines) {
            throw new PatchPolicyViolationError(
              'MALFORMED_DIFF',
              `Hunk count mismatch at @@ -${currentHunk.oldStart},${currentHunk.oldCount} +${currentHunk.newStart},${currentHunk.newCount} @@: expected old ${expectedOldLines}/actual ${actualOldLines}, expected new ${expectedNewLines}/actual ${actualNewLines}`
            );
          }
          currentFile.hunks.push(currentHunk);
          currentHunk = null;
        }

        const match = line.match(/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/);
        if (!match || !match[1] || !match[3]) {
          throw new PatchPolicyViolationError(
            'MALFORMED_DIFF',
            `Malformed hunk header format: '${line}'`
          );
        }

        const oldStart = parseInt(match[1], 10);
        const oldCount = match[2] !== undefined ? parseInt(match[2], 10) : 1;
        const newStart = parseInt(match[3], 10);
        const newCount = match[4] !== undefined ? parseInt(match[4], 10) : 1;

        expectedOldLines = oldCount;
        expectedNewLines = newCount;
        actualOldLines = 0;
        actualNewLines = 0;

        currentHunk = {
          oldStart,
          oldCount,
          newStart,
          newCount,
          lines: [],
        };
        continue;
      }

      // Hunk body lines
      if (currentHunk && currentFile) {
        if (line.startsWith('\\ No newline at end of file')) {
          // Check if applied to old or new
          const lastLine = currentHunk.lines[currentHunk.lines.length - 1];
          if (lastLine?.type === 'deleted') {
            currentHunk.noNewlineOld = true;
          } else if (lastLine?.type === 'added') {
            currentHunk.noNewlineNew = true;
          } else {
            currentHunk.noNewlineOld = true;
            currentHunk.noNewlineNew = true;
          }
          continue;
        }

        const prefix = line[0];
        const content = line.substring(1);

        if (prefix === ' ') {
          actualOldLines++;
          actualNewLines++;
          currentHunk.lines.push({ type: 'context', text: content });
        } else if (prefix === '-') {
          actualOldLines++;
          currentFile.deletedLinesCount++;
          totalChangedLines++;
          currentHunk.lines.push({ type: 'deleted', text: content });
        } else if (prefix === '+') {
          actualNewLines++;
          currentFile.addedLinesCount++;
          totalChangedLines++;
          currentHunk.lines.push({ type: 'added', text: content });
        } else if (line.trim().length === 0 && i === rawLines.length - 1) {
          // Trailing empty newline at end of file
          break;
        } else {
          throw new PatchPolicyViolationError(
            'MALFORMED_DIFF',
            `Invalid line prefix '${prefix}' inside hunk at line ${i + 1}: '${line}'`
          );
        }

        if (totalChangedLines > maxChangedLines) {
          throw new PatchPolicyViolationError(
            'TOO_MANY_LINES',
            `Total changed lines (${totalChangedLines}) exceeds maximum allowed ${maxChangedLines}`
          );
        }
      }
    }

    // Close trailing hunk
    if (currentHunk && currentFile) {
      if (actualOldLines !== expectedOldLines || actualNewLines !== expectedNewLines) {
        throw new PatchPolicyViolationError(
          'MALFORMED_DIFF',
          `Hunk count mismatch at @@ -${currentHunk.oldStart},${currentHunk.oldCount} +${currentHunk.newStart},${currentHunk.newCount} @@: expected old ${expectedOldLines}/actual ${actualOldLines}, expected new ${expectedNewLines}/actual ${actualNewLines}`
        );
      }
      currentFile.hunks.push(currentHunk);
    }

    if (files.length === 0) {
      throw new PatchPolicyViolationError(
        'MALFORMED_DIFF',
        'No valid file diffs found in unified diff'
      );
    }

    return files;
  }

  /**
   * Normalizes path to root-relative POSIX and rejects path traversal,
   * UNC paths, drive letters, and absolute paths.
   */
  public static cleanAndValidatePath(rawPath: string): string {
    let p = rawPath.trim();
    // Strip timestamps or extra tabs/spaces if present (e.g. "path\t2026-10-20...")
    const tabIdx = p.indexOf('\t');
    if (tabIdx !== -1) {
      p = p.substring(0, tabIdx).trim();
    }

    // Strip quotes if quoted
    if ((p.startsWith('"') && p.endsWith('"')) || (p.startsWith("'") && p.endsWith("'"))) {
      p = p.substring(1, p.length - 1);
    }

    // Strip git prefixes: a/ or b/
    if (p.startsWith('a/') || p.startsWith('b/')) {
      p = p.substring(2);
    }

    // Normalize slashes
    p = p.replace(/\\/g, '/');

    // Reject absolute paths, UNC paths, and drive letters
    if (p.startsWith('/') || p.startsWith('//') || /^[a-zA-Z]:/.test(p) || p.includes('\0')) {
      throw new PatchPolicyViolationError(
        'OUTSIDE_ROOT',
        `Absolute or invalid path rejected: '${rawPath}'`
      );
    }

    // Reject path traversal
    const segments = p.split('/');
    if (segments.some((s) => s === '..')) {
      throw new PatchPolicyViolationError(
        'OUTSIDE_ROOT',
        `Path traversal ('..') detected: '${rawPath}'`
      );
    }

    // Filter empty segments
    const clean = segments.filter((s) => s.length > 0 && s !== '.').join('/');
    if (!clean) {
      throw new PatchPolicyViolationError('OUTSIDE_ROOT', 'Empty path after normalization');
    }

    return clean;
  }
}
