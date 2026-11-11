import path from 'node:path';
import type { AiCitation } from '@secureship/contracts';
import type { SlicedFindingContext } from '@secureship/context-slicer';
import type { RawModelCitation } from './triage-schema.js';

export interface CitationVerificationResult {
  valid: boolean;
  failureReason?: string;
  verifiedCitations: AiCitation[];
}

export class CitationVerifier {
  /**
   * Deterministically verifies that all citations correspond to actual lines and
   * substring quotes in the provided code slice (A6, T4).
   */
  public static verifyCitations(
    citations: RawModelCitation[],
    slice: SlicedFindingContext,
    isFalsePositiveClaim: boolean
  ): CitationVerificationResult {
    // A false-positive claim strictly requires at least one verified citation
    if (isFalsePositiveClaim && (!citations || citations.length === 0)) {
      return {
        valid: false,
        failureReason: 'False positive verdict requires at least one concrete code citation.',
        verifiedCitations: [],
      };
    }

    const verifiedCitations: AiCitation[] = [];
    const sliceLines = slice.primarySlice.split('\n');
    const startLine = slice.primarySliceLines.start;
    const endLine = slice.primarySliceLines.end;

    const normPrimary = path.normalize(slice.filePath).replace(/\\/g, '/');
    const allowedFiles = new Set<string>([
      normPrimary,
      ...slice.usageSites.map((u) => path.normalize(u.filePath).replace(/\\/g, '/')),
    ]);

    for (let i = 0; i < citations.length; i++) {
      const citation = citations[i]!;
      const quote = citation.quote.trim();
      const citedLine = citation.line;

      if (!quote) {
        return {
          valid: false,
          failureReason: `Citation at index ${i} has an empty quote.`,
          verifiedCitations: [],
        };
      }

      // Bug 2 Fix: Validate citation file path against primary slice and usage sites
      const rawFile = citation.file || slice.filePath;
      const normCitation = path.normalize(rawFile).replace(/\\/g, '/');

      if (!allowedFiles.has(normCitation)) {
        return {
          valid: false,
          failureReason: `Citation references un-sliced or disallowed file '${citation.file}'.`,
          verifiedCitations: [],
        };
      }

      let matched = false;

      // Check primary slice if citation matches primary slice file
      if (normCitation === normPrimary && citedLine >= startLine && citedLine <= endLine) {
        const lineIdx = citedLine - startLine;
        // Check exact cited line or +/- 1 line tolerance for off-by-one model outputs
        const candidateIndices = [lineIdx, lineIdx - 1, lineIdx + 1];
        for (const idx of candidateIndices) {
          if (idx >= 0 && idx < sliceLines.length) {
            const lineContent = sliceLines[idx]!;
            const trimmed = lineContent.trim();
            // Bug 1 Fix: Ensure lineContent has at least 3 characters to prevent empty-line substring bypass
            if (trimmed.length < 3) {
              continue;
            }
            if (
              lineContent.toLowerCase().includes(quote.toLowerCase()) ||
              quote.toLowerCase().includes(trimmed.toLowerCase())
            ) {
              matched = true;
              break;
            }
          }
        }
      }

      // Check usage sites if not matched in primary slice
      if (!matched && slice.usageSites.length > 0) {
        for (const usage of slice.usageSites) {
          const normUsage = path.normalize(usage.filePath).replace(/\\/g, '/');
          if (normCitation === normUsage || !citation.file) {
            if (citedLine >= usage.startLine && citedLine <= usage.endLine) {
              const usageLines = usage.snippet.split('\n');
              for (const uLine of usageLines) {
                const uTrimmed = uLine.trim();
                // Bug 1 Fix: Ensure usage line has at least 3 characters
                if (uTrimmed.length < 3) {
                  continue;
                }
                if (
                  uLine.toLowerCase().includes(quote.toLowerCase()) ||
                  quote.toLowerCase().includes(uTrimmed.toLowerCase())
                ) {
                  matched = true;
                  break;
                }
              }
            }
          }
          if (matched) break;
        }
      }

      if (!matched) {
        return {
          valid: false,
          failureReason: `Citation quote '${quote.slice(0, 50)}' does not match source content at line ${citedLine}.`,
          verifiedCitations: [],
        };
      }

      verifiedCitations.push({
        file: citation.file || slice.filePath,
        line: citedLine,
        quote,
      });
    }

    return {
      valid: true,
      verifiedCitations,
    };
  }
}
