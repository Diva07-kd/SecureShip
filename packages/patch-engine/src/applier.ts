import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { PatchPolicyViolationError, type ParsedDiffFile } from './diff-parser.js';

export interface EolAndBomInfo {
  hasBom: boolean;
  eol: '\r\n' | '\n';
  hasTrailingNewline: boolean;
}

export class PatchApplier {
  /**
   * Detects BOM, line ending (CRLF vs LF), and trailing newline of text.
   */
  public static analyzeFormat(text: string): EolAndBomInfo {
    const hasBom = text.startsWith('\uFEFF');
    const content = hasBom ? text.substring(1) : text;

    // Detect CRLF if CRLF count > 0 and greater than or equal to standalone LF
    const crlfMatches = content.match(/\r\n/g)?.length ?? 0;
    const lfMatches = content.match(/(?<!\r)\n/g)?.length ?? 0;
    const eol: '\r\n' | '\n' = crlfMatches > 0 && crlfMatches >= lfMatches ? '\r\n' : '\n';

    const hasTrailingNewline = content.endsWith('\n') || content.endsWith('\r\n');

    return { hasBom, eol, hasTrailingNewline };
  }

  /**
   * Applies a parsed unified diff file to original file text.
   * Pure function: does not perform filesystem operations.
   */
  public static apply(originalText: string, parsedFile: ParsedDiffFile): string {
    const format = PatchApplier.analyzeFormat(originalText);

    // Strip BOM for line processing
    const rawContent = format.hasBom ? originalText.substring(1) : originalText;

    // Check for inconsistent EOL in originalText
    const lines = rawContent.split(/\r?\n/);
    // If text ended with newline, split produces an empty trailing element
    let hadTrailingNewline = false;
    if (lines.length > 0 && lines[lines.length - 1] === '') {
      hadTrailingNewline = true;
      lines.pop(); // Remove empty trailing line for 1-based indexing
    }

    // Verify patch line endings consistency
    for (const hunk of parsedFile.hunks) {
      for (const line of hunk.lines) {
        if (line.text.includes('\r')) {
          throw new PatchPolicyViolationError(
            'EOL_INCONSISTENT',
            'Patch line content contains embedded carriage return \\r'
          );
        }
      }
    }

    // Sort hunks by oldStart ascending to apply in order with line offset tracking
    const sortedHunks = [...parsedFile.hunks].sort((a, b) => a.oldStart - b.oldStart);

    let lineOffset = 0;
    let newHasTrailingNewline = format.hasTrailingNewline || hadTrailingNewline;

    for (let hunkIdx = 0; hunkIdx < sortedHunks.length; hunkIdx++) {
      const hunk = sortedHunks[hunkIdx]!;
      const expectedOldLines: string[] = [];
      const replacementLines: string[] = [];

      for (const l of hunk.lines) {
        if (l.type === 'context' || l.type === 'deleted') {
          expectedOldLines.push(l.text);
        }
        if (l.type === 'context' || l.type === 'added') {
          replacementLines.push(l.text);
        }
      }

      // Expected line index based on hunk header adjusted by previous line offset
      const targetIndex = hunk.oldStart - 1 + lineOffset;

      // Find match: exact at targetIndex, or within +/-20 lines
      const matchIndex = PatchApplier.findMatchIndex(lines, expectedOldLines, targetIndex);
      if (matchIndex === -1) {
        throw new PatchPolicyViolationError(
          'CONTEXT_MISMATCH',
          `Context mismatch applying hunk @@ -${hunk.oldStart},${hunk.oldCount} +${hunk.newStart},${hunk.newCount} @@ for file '${parsedFile.oldPath}'`
        );
      }

      // Splice replacement lines
      lines.splice(matchIndex, expectedOldLines.length, ...replacementLines);

      // Update line offset
      const hunkLineDiff = replacementLines.length - expectedOldLines.length;
      lineOffset += hunkLineDiff + (matchIndex - targetIndex);

      if (hunk.noNewlineNew) {
        newHasTrailingNewline = false;
      }
    }

    // Reconstruct file text
    let result = lines.join(format.eol);
    if (newHasTrailingNewline && result.length > 0) {
      result += format.eol;
    }

    if (format.hasBom) {
      result = '\uFEFF' + result;
    }

    return result;
  }

  /**
   * Finds the exact line index matching expectedOldLines within +/- 20 lines of targetIndex.
   * If exact match at targetIndex, returns targetIndex immediately.
   * If multiple matches exist in window, fails closed with CONTEXT_MISMATCH (no ambiguity).
   */
  private static findMatchIndex(
    lines: string[],
    expectedOldLines: string[],
    targetIndex: number
  ): number {
    if (expectedOldLines.length === 0) {
      return Math.max(0, Math.min(targetIndex, lines.length));
    }

    // 1. Check exact position first
    if (PatchApplier.matchesAt(lines, expectedOldLines, targetIndex)) {
      return targetIndex;
    }

    // 2. Search +/- 20 lines window
    const windowRadius = 20;
    const minIndex = Math.max(0, targetIndex - windowRadius);
    const maxIndex = Math.min(lines.length - expectedOldLines.length, targetIndex + windowRadius);

    const matches: number[] = [];
    for (let idx = minIndex; idx <= maxIndex; idx++) {
      if (idx === targetIndex) continue; // Already checked
      if (PatchApplier.matchesAt(lines, expectedOldLines, idx)) {
        matches.push(idx);
      }
    }

    if (matches.length === 1) {
      return matches[0]!;
    }

    if (matches.length > 1) {
      throw new PatchPolicyViolationError(
        'CONTEXT_MISMATCH',
        `Ambiguous context match: found ${matches.length} matching locations within +/- 20 lines`
      );
    }

    return -1;
  }

  private static matchesAt(lines: string[], expected: string[], startIndex: number): boolean {
    if (startIndex < 0 || startIndex + expected.length > lines.length) {
      return false;
    }

    for (let i = 0; i < expected.length; i++) {
      if (lines[startIndex + i] !== expected[i]) {
        return false;
      }
    }

    return true;
  }

  /**
   * Atomically writes content to target file via temp-file + rename.
   * Preserves file mode/permissions if the file exists.
   */
  public static atomicWrite(targetPath: string, content: string, explicitMode?: number): void {
    const dir = path.dirname(targetPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    let mode = explicitMode;
    if (mode === undefined && fs.existsSync(targetPath)) {
      try {
        const stat = fs.statSync(targetPath);
        mode = stat.mode;
      } catch {
        // Fallback
      }
    }

    const randomSuffix = crypto.randomBytes(8).toString('hex');
    const tempFile = path.join(dir, `.secureship_tmp_${path.basename(targetPath)}_${randomSuffix}`);

    try {
      fs.writeFileSync(tempFile, content, {
        encoding: 'utf8',
        mode: mode ?? 0o644,
      });
      fs.renameSync(tempFile, targetPath);
    } catch (err) {
      try {
        if (fs.existsSync(tempFile)) {
          fs.unlinkSync(tempFile);
        }
      } catch {
        // Ignore cleanup failure
      }
      throw err;
    }
  }
}
