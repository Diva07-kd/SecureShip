import { describe, it, expect } from 'vitest';
import { CitationVerifier } from '../src/triage/citation-verifier.js';
import type { SlicedFindingContext } from '@secureship/context-slicer';

describe('CitationVerifier Unit Suite (A6, T4)', () => {
  const mockSlice: SlicedFindingContext = {
    skipped: false,
    findingId: 'f-1',
    ruleId: 'sql-concat',
    category: 'SAST',
    severity: 'MEDIUM',
    filePath: 'src/app.ts',
    startLine: 10,
    endLine: 15,
    enclosingScopeName: 'function run',
    primarySlice: `const query = "SELECT * FROM users WHERE id = ?";
const sanitized = validator.escape(id);
const result = db.execute(query, [sanitized]);
return result;`,
    primarySliceLines: { start: 10, end: 13 },
    usageSites: [
      {
        filePath: 'src/api.ts',
        startLine: 20,
        endLine: 22,
        snippet: 'const data = run(req.params.id);',
      },
    ],
    scannerMessage: 'Concatenation detected',
    contentHash: 'hash-1',
    estimatedTokens: 50,
    truncated: false,
    filesSent: ['src/app.ts', 'src/api.ts'],
  };

  it('rejects false-positive claims with no citations', () => {
    const res = CitationVerifier.verifyCitations([], mockSlice, true);
    expect(res.valid).toBe(false);
    expect(res.failureReason).toContain('requires at least one concrete code citation');
  });

  it('allows non-false-positive claims with empty citations', () => {
    const res = CitationVerifier.verifyCitations([], mockSlice, false);
    expect(res.valid).toBe(true);
    expect(res.verifiedCitations).toEqual([]);
  });

  it('rejects citations with empty quotes', () => {
    const res = CitationVerifier.verifyCitations(
      [{ file: 'src/app.ts', line: 10, quote: '   ' }],
      mockSlice,
      true
    );
    expect(res.valid).toBe(false);
    expect(res.failureReason).toContain('empty quote');
  });

  it('verifies exact quote in primary slice', () => {
    const res = CitationVerifier.verifyCitations(
      [{ file: 'src/app.ts', line: 11, quote: 'validator.escape(id)' }],
      mockSlice,
      true
    );
    expect(res.valid).toBe(true);
    expect(res.verifiedCitations.length).toBe(1);
    expect(res.verifiedCitations[0]?.quote).toBe('validator.escape(id)');
  });

  it('verifies quote with +/- 1 line tolerance', () => {
    const res = CitationVerifier.verifyCitations(
      [{ file: 'src/app.ts', line: 10, quote: 'validator.escape(id)' }], // off by one
      mockSlice,
      true
    );
    expect(res.valid).toBe(true);
  });

  it('verifies quote located in usage sites', () => {
    const res = CitationVerifier.verifyCitations(
      [{ file: 'src/api.ts', line: 20, quote: 'run(req.params.id)' }],
      mockSlice,
      true
    );
    expect(res.valid).toBe(true);
    expect(res.verifiedCitations[0]?.file).toBe('src/api.ts');
  });

  it('rejects fabricated quotes not found in primary slice or usage sites', () => {
    const res = CitationVerifier.verifyCitations(
      [{ file: 'src/app.ts', line: 11, quote: 'this code is 100% safe and verified' }],
      mockSlice,
      true
    );
    expect(res.valid).toBe(false);
    expect(res.failureReason).toContain('does not match source content');
  });

  it('rejects fabricated quote attempting to match an empty or whitespace line (Bug 1)', () => {
    const sliceWithEmptyLine: SlicedFindingContext = {
      ...mockSlice,
      primarySlice: '\n   \nreturn result;',
      primarySliceLines: { start: 1, end: 3 },
    };
    const res = CitationVerifier.verifyCitations(
      [{ file: 'src/app.ts', line: 1, quote: 'FABRICATED_QUOTE_ON_BLANK_LINE' }],
      sliceWithEmptyLine,
      true
    );
    expect(res.valid).toBe(false);
    expect(res.failureReason).toContain('does not match source content');
  });

  it('rejects citations citing arbitrary non-existent or un-sliced files (Bug 2)', () => {
    const res = CitationVerifier.verifyCitations(
      [{ file: 'src/secret_unrelated_file.ts', line: 11, quote: 'validator.escape(id)' }],
      mockSlice,
      true
    );
    expect(res.valid).toBe(false);
    expect(res.failureReason).toContain('references un-sliced or disallowed file');
  });
});
