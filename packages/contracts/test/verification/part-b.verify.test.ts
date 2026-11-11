import { describe, it, expect } from 'vitest';
import {
  AiTriageSchema,
  ScanReportSchema,
  SuppressionReasonCodeSchema,
  UserConfigSchema,
} from '../../src/index.js';

describe('Part B Verification: Contracts & Schemas (B1, B2, B3)', () => {
  it('B1: aiTriage schema strictness and length boundaries', () => {
    const validTriage = {
      verdict: 'LIKELY_FALSE_POSITIVE' as const,
      confidence: 'HIGH' as const,
      rationale: 'Valid explanation within 600 character limit.',
      citations: [
        { file: 'src/util.ts', line: 10, quote: 'const x = sanitize(v);' },
        { file: 'src/app.ts', line: 42, quote: 'return x;' },
      ],
      exploitabilityNotes: 'Notes within 300 character limit.',
      model: 'test-model-4',
      promptVersion: '1.0.0',
      cached: false,
      consistency: { samples: 2, agreed: true },
      tokens: { in: 1500, out: 120 },
      injectionFlag: false,
    };

    // 1. Valid parse succeeds
    expect(AiTriageSchema.safeParse(validTriage).success).toBe(true);

    // 2. Rationale > 600 rejected
    const tooLongRationale = {
      ...validTriage,
      rationale: 'A'.repeat(601),
    };
    expect(AiTriageSchema.safeParse(tooLongRationale).success).toBe(false);

    // 3. Citations > 5 items rejected
    const tooManyCitations = {
      ...validTriage,
      citations: Array.from({ length: 6 }, (_, i) => ({
        file: `src/f${i}.ts`,
        line: i + 1,
        quote: `code ${i}`,
      })),
    };
    expect(AiTriageSchema.safeParse(tooManyCitations).success).toBe(false);

    // 4. Citation quote > 200 chars rejected
    const tooLongQuote = {
      ...validTriage,
      citations: [{ file: 'src/test.ts', line: 1, quote: 'Q'.repeat(201) }],
    };
    expect(AiTriageSchema.safeParse(tooLongQuote).success).toBe(false);

    // 5. Unknown verdict rejected
    const unknownVerdict = {
      ...validTriage,
      verdict: 'NOT_A_REAL_VERDICT',
    };
    expect(AiTriageSchema.safeParse(unknownVerdict).success).toBe(false);

    // 6. Exploitability notes > 300 rejected
    const tooLongExploit = {
      ...validTriage,
      exploitabilityNotes: 'E'.repeat(301),
    };
    expect(AiTriageSchema.safeParse(tooLongExploit).success).toBe(false);
  });

  it('B1: Backward compatibility: Report 1.0 and 1.1 parse cleanly, writers emit 1.2', () => {
    // Phase 1 Report 1.0 sample (no reachability, no gate3/ai)
    const report10 = {
      schemaVersion: '1.0',
      tool: { name: 'secureship', version: '0.1.0' },
      target: 'C:/dev/sample-app',
      mode: 'FULL',
      startedAt: '2026-10-18T10:00:00.000Z',
      durationMs: 450,
      scanners: [{ name: 'opengrep', status: 'SUCCESS', durationMs: 200, rawFindingCount: 1 }],
      findings: [
        {
          id: 'find-10',
          fingerprint: '1'.repeat(64),
          ruleId: 'sql-inj',
          scannerName: 'opengrep',
          category: 'SAST',
          severity: 'HIGH',
          confidence: 'HIGH',
          reachability: 'UNKNOWN',
          location: { filePath: 'app.ts', startLine: 1, endLine: 2 },
          scopeTag: 'PRODUCTION',
          upstreamValidationStatus: 'UNKNOWN',
          verificationStatus: 'UNVERIFIED',
          title: 'SQL Inj',
          description: 'SQL inj desc',
          evidence: [
            {
              scannerName: 'opengrep',
              scannerRuleId: 'sql-inj',
              message: 'SQL injection detected',
            },
          ],
          createdAt: '2026-10-18T10:00:00.000Z',
        },
      ],
      suppressed: [],
      summary: {
        totalRaw: 1,
        totalReported: 1,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 1, SCA: 0, SECRET: 0, IAC: 0 },
        byReachability: {
          REACHABLE_CALL_PATH: 0,
          REACHABLE_IMPORT: 0,
          UNREACHABLE: 0,
          UNKNOWN: 1,
        },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 0,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
          GATE2_UNREACHABLE: 0,
          GATE3_LIKELY_FALSE_POSITIVE: 0,
        },
      },
      warnings: [],
    };
    expect(ScanReportSchema.safeParse(report10).success).toBe(true);

    // Phase 2/3 Report 1.1 sample (with reachability, no ai)
    const report11 = {
      ...report10,
      schemaVersion: '1.1',
    };
    expect(ScanReportSchema.safeParse(report11).success).toBe(true);

    // Default schema version for new report instantiation is 1.2
    const defaultParsed = ScanReportSchema.parse({
      ...report10,
      schemaVersion: undefined,
    });
    expect(defaultParsed.schemaVersion).toBe('1.2');
  });

  it('B2: GATE3_LIKELY_FALSE_POSITIVE exists, byAiVerdict optional on read, no dollar-cost fields', () => {
    // 1. GATE3_LIKELY_FALSE_POSITIVE
    expect(SuppressionReasonCodeSchema.safeParse('GATE3_LIKELY_FALSE_POSITIVE').success).toBe(true);

    // 2. byAiVerdict optional on read
    const baseSummary = {
      totalRaw: 1,
      totalReported: 1,
      totalSuppressed: 0,
      totalOutOfScope: 0,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { SAST: 1, SCA: 0, SECRET: 0, IAC: 0 },
      byReachability: {
        REACHABLE_CALL_PATH: 0,
        REACHABLE_IMPORT: 0,
        UNREACHABLE: 0,
        UNKNOWN: 1,
      },
      suppressedByReason: {
        GATE1_TEST_OR_MOCK: 0,
        GATE1_EXAMPLE: 0,
        GATE1_DOCUMENTATION: 0,
        USER_IGNORE_RULE: 0,
        BASELINE_KNOWN: 0,
        GATE2_UNREACHABLE: 0,
        GATE3_LIKELY_FALSE_POSITIVE: 0,
      },
    };

    // Valid without byAiVerdict
    const reportWithoutAiVerdict = {
      schemaVersion: '1.2' as const,
      tool: { name: 'secureship', version: '0.1.0' },
      target: 'C:/dev/app',
      mode: 'FULL' as const,
      startedAt: new Date().toISOString(),
      durationMs: 100,
      scanners: [],
      findings: [],
      suppressed: [],
      summary: baseSummary,
      warnings: [],
    };
    const parsedNoAiVerdict = ScanReportSchema.safeParse(reportWithoutAiVerdict);
    expect(parsedNoAiVerdict.success).toBe(true);

    // 3. AI summary block validates
    const reportWithAiSummary = {
      ...reportWithoutAiVerdict,
      summary: {
        ...baseSummary,
        byAiVerdict: {
          LIKELY_TRUE_POSITIVE: 1,
          LIKELY_FALSE_POSITIVE: 0,
          NEEDS_HUMAN_REVIEW: 0,
        },
      },
      ai: {
        provider: 'openai',
        model: 'gpt-4o-mini',
        host: '127.0.0.1:11434',
        deterministic: true,
        findingsConsidered: 1,
        findingsSent: 1,
        findingsSkipped: [],
        tokensIn: 800,
        tokensOut: 60,
        filesSent: ['app.ts'],
        truncatedSlices: 0,
        cacheHits: 0,
        warnings: [],
      },
    };
    expect(ScanReportSchema.safeParse(reportWithAiSummary).success).toBe(true);

    // 4. No dollar-cost fields: ScanReportSchema and AiExecutionSummarySchema must not accept cost fields
    const reportWithDollarCost = {
      ...reportWithAiSummary,
      ai: {
        ...reportWithAiSummary.ai,
        dollarCost: 0.05,
        estimatedCost: '$0.05',
      },
    };
    // Zod strip/strict checks
    const parsedWithCost = ScanReportSchema.parse(reportWithDollarCost);
    expect((parsedWithCost.ai as Record<string, unknown>).dollarCost).toBeUndefined();
    expect((parsedWithCost.ai as Record<string, unknown>).estimatedCost).toBeUndefined();
  });

  it('B3: gate3 config schema defaults', () => {
    const parsedDefault = UserConfigSchema.parse({});
    expect(parsedDefault.gate3.neverSuppressSeverities).toEqual(['CRITICAL', 'HIGH']);
    expect(parsedDefault.gate3.minConfidence).toBe('HIGH');
    expect(parsedDefault.gate3.consistencyChecks).toBe(2);
    expect(parsedDefault.gate3.maxFindings).toBe(25);
    expect(parsedDefault.gate3.budgetTokens).toBe(200000);
    expect(parsedDefault.gate3.mode).toBe('annotate');
  });
});
