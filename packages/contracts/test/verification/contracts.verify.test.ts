import { describe, it, expect } from 'vitest';
import * as Contracts from '../../src/index.js';

describe('Part B Verification: @secureship/contracts', () => {
  it('B1: exports all required schemas and models', () => {
    const requiredExports = [
      'SeveritySchema',
      'ConfidenceSchema',
      'ReachabilitySchema',
      'FindingCategorySchema',
      'VerificationStatusSchema',
      'UpstreamValidationStatusSchema',
      'ScopeTagSchema',
      'FindingLocationSchema',
      'ScannerEvidenceSchema',
      'NormalizedFindingSchema',
      'ScanExecutionStatusSchema',
      'ScanExecutionResultSchema',
      'DetectedLanguageSchema',
      'DetectedPackageManagerSchema',
      'ProjectProfileSchema',
      'LicenseTierSchema',
      'TierCapabilitiesSchema',
      'TIER_CAPABILITY_DEFAULTS',
    ];

    for (const exp of requiredExports) {
      expect(Contracts).toHaveProperty(exp);
      expect((Contracts as Record<string, unknown>)[exp]).toBeDefined();
    }
  });

  it('B2: enum validation and rejection of invalid values', () => {
    // SeveritySchema
    expect(Contracts.SeveritySchema.safeParse('CRITICAL').success).toBe(true);
    expect(Contracts.SeveritySchema.safeParse('HIGH').success).toBe(true);
    expect(Contracts.SeveritySchema.safeParse('critical').success).toBe(false); // lowercase rejected
    expect(Contracts.SeveritySchema.safeParse('').success).toBe(false);
    expect(Contracts.SeveritySchema.safeParse(null).success).toBe(false);
    expect(Contracts.SeveritySchema.safeParse(undefined).success).toBe(false);
    expect(Contracts.SeveritySchema.safeParse(123).success).toBe(false);
    expect(Contracts.SeveritySchema.safeParse('UNKNOWN_VAL').success).toBe(false);

    // ConfidenceSchema
    expect(Contracts.ConfidenceSchema.safeParse('HIGH').success).toBe(true);
    expect(Contracts.ConfidenceSchema.safeParse('high').success).toBe(false);
    expect(Contracts.ConfidenceSchema.safeParse(null).success).toBe(false);

    // ReachabilitySchema
    expect(Contracts.ReachabilitySchema.safeParse('REACHABLE_CALL_PATH').success).toBe(true);
    expect(Contracts.ReachabilitySchema.safeParse('REACHABLE_IMPORT').success).toBe(true);
    expect(Contracts.ReachabilitySchema.safeParse('UNREACHABLE').success).toBe(true);
    expect(Contracts.ReachabilitySchema.safeParse('UNKNOWN').success).toBe(true);
    expect(Contracts.ReachabilitySchema.safeParse('reachable').success).toBe(false);

    // FindingCategorySchema
    expect(Contracts.FindingCategorySchema.safeParse('SAST').success).toBe(true);
    expect(Contracts.FindingCategorySchema.safeParse('SCA').success).toBe(true);
    expect(Contracts.FindingCategorySchema.safeParse('SECRET').success).toBe(true);
    expect(Contracts.FindingCategorySchema.safeParse('IAC').success).toBe(true);
    expect(Contracts.FindingCategorySchema.safeParse('sast').success).toBe(false);

    // VerificationStatusSchema
    expect(Contracts.VerificationStatusSchema.safeParse('UNVERIFIED').success).toBe(true);
    expect(Contracts.VerificationStatusSchema.safeParse('VERIFIED_STATIC').success).toBe(true);
    expect(Contracts.VerificationStatusSchema.safeParse('VERIFIED_RUNTIME').success).toBe(true);
    expect(Contracts.VerificationStatusSchema.safeParse('FAILED').success).toBe(true);
    expect(Contracts.VerificationStatusSchema.safeParse('INCONCLUSIVE').success).toBe(true);
    expect(Contracts.VerificationStatusSchema.safeParse('verified').success).toBe(false);

    // ScopeTagSchema
    expect(Contracts.ScopeTagSchema.safeParse('PRODUCTION').success).toBe(true);
    expect(Contracts.ScopeTagSchema.safeParse('TEST_OR_MOCK').success).toBe(true);
    expect(Contracts.ScopeTagSchema.safeParse('DOCUMENTATION').success).toBe(true);
    expect(Contracts.ScopeTagSchema.safeParse('EXAMPLE').success).toBe(true);
    expect(Contracts.ScopeTagSchema.safeParse('prod').success).toBe(false);
  });

  it('B3: NormalizedFinding schema parsing, required fields, and fingerprint validation', () => {
    const validSample = {
      id: 'find-123',
      fingerprint: 'a'.repeat(64),
      ruleId: 'sql-injection',
      scannerName: 'opengrep' as const,
      category: 'SAST' as const,
      severity: 'HIGH' as const,
      confidence: 'MEDIUM' as const,
      reachability: 'UNKNOWN' as const,
      location: {
        filePath: 'src/db.ts',
        startLine: 10,
        endLine: 12,
      },
      upstreamValidationStatus: 'UNKNOWN' as const,
      verificationStatus: 'UNVERIFIED' as const,
      scopeTag: 'PRODUCTION' as const,
      title: 'SQL Injection in Query',
      description: 'Unescaped user input',
      cweIds: ['CWE-89'],
      evidence: [
        {
          scannerName: 'opengrep' as const,
          scannerRuleId: 'sql-injection',
          message: 'Potential vulnerability',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    expect(Contracts.NormalizedFindingSchema.safeParse(validSample).success).toBe(true);

    // Invalid fingerprint length
    expect(
      Contracts.NormalizedFindingSchema.safeParse({
        ...validSample,
        fingerprint: 'short_hash',
      }).success
    ).toBe(false);

    // Required fields missing
    const requiredKeys = [
      'id',
      'fingerprint',
      'ruleId',
      'scannerName',
      'category',
      'severity',
      'confidence',
      'location',
      'title',
      'description',
      'evidence',
      'createdAt',
    ] as const;
    for (const key of requiredKeys) {
      const copy: Record<string, unknown> = { ...validSample };
      delete copy[key];
      expect(Contracts.NormalizedFindingSchema.safeParse(copy).success).toBe(false);
    }

    // Line validation: negative line numbers
    expect(
      Contracts.FindingLocationSchema.safeParse({
        filePath: 'src/a.ts',
        startLine: -1,
        endLine: 5,
      }).success
    ).toBe(false);
  });

  it('B4: FindingLocation.filePath handling of backslashes and relative traversal', () => {
    // Observe schema behavior on backslashes and relative traversal
    const backslashResult = Contracts.FindingLocationSchema.safeParse({
      filePath: 'src\\app\\a.ts',
      startLine: 1,
      endLine: 1,
    });
    expect(backslashResult.success).toBe(true);

    const traversalResult = Contracts.FindingLocationSchema.safeParse({
      filePath: '../../etc/passwd',
      startLine: 1,
      endLine: 1,
    });
    expect(traversalResult.success).toBe(true);
    // Note: FindingLocationSchema accepts string path; normalization and path boundary checks are enforced in ProjectDetector / FindingCorrelator.
  });

  it('B5: TierCapabilities representation and FREE_BYOK gate defaults', () => {
    const freeDefaults = Contracts.TIER_CAPABILITY_DEFAULTS.FREE_BYOK;
    expect(freeDefaults.tier).toBe('FREE_BYOK');
    expect(freeDefaults.maxMonthlyAiFixes).toBe(15);
    expect(freeDefaults.allowCrossFileAstGraph).toBe(false);
    expect(freeDefaults.allowShadowWorktreeSandbox).toBe(false);
    expect(freeDefaults.allowCiCdGatekeeper).toBe(false);
    expect(freeDefaults.allowSignedComplianceExport).toBe(false);
    expect(freeDefaults.allowAirGappedOnPrem).toBe(false);

    const proDefaults = Contracts.TIER_CAPABILITY_DEFAULTS.PRO_TEAM;
    expect(proDefaults.allowCrossFileAstGraph).toBe(true);
    expect(proDefaults.allowShadowWorktreeSandbox).toBe(true);
    expect(proDefaults.allowCiCdGatekeeper).toBe(true);
    expect(proDefaults.allowSignedComplianceExport).toBe(true);

    const enterpriseDefaults = Contracts.TIER_CAPABILITY_DEFAULTS.ENTERPRISE;
    expect(enterpriseDefaults.maxMonthlyAiFixes).toBeNull(); // Unlimited
    expect(enterpriseDefaults.allowAirGappedOnPrem).toBe(true);
  });

  it('B6: Extra key behavior on schemas', () => {
    const findingWithExtra = {
      id: 'f-1',
      fingerprint: 'b'.repeat(64),
      ruleId: 'r-1',
      scannerName: 'opengrep' as const,
      category: 'SAST' as const,
      severity: 'INFO' as const,
      confidence: 'LOW' as const,
      location: {
        filePath: 'src/a.ts',
        startLine: 1,
        endLine: 1,
      },
      title: 'T',
      description: 'D',
      evidence: [
        {
          scannerName: 'opengrep' as const,
          scannerRuleId: 'r-1',
          message: 'msg',
        },
      ],
      createdAt: new Date().toISOString(),
      unexpectedExtraKey: 'malicious_or_extra_field',
    };

    const parsed = Contracts.NormalizedFindingSchema.safeParse(findingWithExtra);
    expect(parsed.success).toBe(true);
    // Standard Zod object strips extra keys by default unless .passthrough() or .strict()
    if (parsed.success) {
      expect((parsed.data as Record<string, unknown>).unexpectedExtraKey).toBeUndefined();
    }
  });

  it('B7: ReachabilityDetailSchema and ReachabilityEvidenceKindSchema validation', () => {
    const validDetail = {
      verdict: 'REACHABLE_IMPORT' as const,
      analysisConfidence: 'HIGH' as const,
      evidence: {
        kind: 'PACKAGE_IMPORTED' as const,
        chain: ['src/index.ts', 'src/api.ts'],
        via: ['express'],
        notes: 'Imported in production entrypoint',
      },
      limitations: ['Import-level analysis only'],
    };

    const parsed = Contracts.ReachabilityDetailSchema.safeParse(validDetail);
    expect(parsed.success).toBe(true);
    expect(Contracts.ReachabilityEvidenceKindSchema.safeParse('TEST_ONLY_IMPORT').success).toBe(
      true
    );

    // Finding with reachabilityDetail attached
    const findingWithReachability = {
      id: 'f-reach-1',
      fingerprint: 'c'.repeat(64),
      ruleId: 'r-1',
      scannerName: 'osv-scanner' as const,
      category: 'SCA' as const,
      severity: 'HIGH' as const,
      confidence: 'HIGH' as const,
      reachability: 'REACHABLE_IMPORT' as const,
      reachabilityDetail: validDetail,
      location: {
        filePath: 'package.json',
        startLine: 1,
        endLine: 1,
      },
      title: 'Vulnerable package',
      description: 'Test vulnerability',
      evidence: [
        {
          scannerName: 'osv-scanner' as const,
          scannerRuleId: 'GHSA-1234',
          message: 'Vulnerable',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    const parsedFinding = Contracts.NormalizedFindingSchema.safeParse(findingWithReachability);
    expect(parsedFinding.success).toBe(true);
    if (parsedFinding.success) {
      expect(parsedFinding.data.reachabilityDetail?.verdict).toBe('REACHABLE_IMPORT');
      expect(parsedFinding.data.reachabilityDetail?.evidence.kind).toBe('PACKAGE_IMPORTED');
    }
  });

  it('B8: SuppressionReasonCodeSchema includes GATE2_UNREACHABLE', () => {
    expect(Contracts.SuppressionReasonCodeSchema.safeParse('GATE2_UNREACHABLE').success).toBe(true);
    expect(Contracts.SuppressionReasonCodeSchema.safeParse('GATE1_TEST_OR_MOCK').success).toBe(
      true
    );
    expect(Contracts.SuppressionReasonCodeSchema.safeParse('UNKNOWN_REASON').success).toBe(false);
  });

  it('B9: Gate2ConfigSchema validation and defaults', () => {
    const emptyConfig = Contracts.ConfigSchema.parse({});
    expect(emptyConfig.gate2.mode).toBe('annotate');
    expect(emptyConfig.gate2.neverSuppressSeverities).toEqual(['CRITICAL']);
    expect(emptyConfig.gate2.maxFileBytes).toBe(1_048_576);
    expect(emptyConfig.gate2.parseTimeoutMs).toBe(5000);

    const customGate2 = Contracts.Gate2ConfigSchema.parse({
      mode: 'suppress',
      neverSuppressSeverities: ['CRITICAL', 'HIGH'],
      entrypoints: ['src/main.ts'],
      maxFileBytes: 500_000,
    });
    expect(customGate2.mode).toBe('suppress');
    expect(customGate2.neverSuppressSeverities).toEqual(['CRITICAL', 'HIGH']);
    expect(customGate2.entrypoints).toEqual(['src/main.ts']);
    expect(customGate2.maxFileBytes).toBe(500_000);

    // Invalid mode rejected
    expect(Contracts.Gate2ConfigSchema.safeParse({ mode: 'invalid' }).success).toBe(false);
  });

  it('B10: ScanReportSchema backwards compatibility (A10) with v1.0 and v1.1', () => {
    // Real Phase 2 v1.0 report without byReachability
    const v1Report = {
      schemaVersion: '1.0' as const,
      tool: { name: 'secureship', version: '0.1.0' },
      target: 'C:/dev/target',
      mode: 'FULL' as const,
      startedAt: new Date().toISOString(),
      durationMs: 1250,
      scanners: [
        {
          name: 'gitleaks' as const,
          status: 'SUCCESS' as const,
          durationMs: 350,
          rawFindingCount: 0,
        },
      ],
      findings: [],
      suppressed: [],
      summary: {
        totalRaw: 0,
        totalReported: 0,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0 },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 0,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
          GATE2_UNREACHABLE: 0,
        },
      },
      warnings: [],
    };

    const parsedV1 = Contracts.ScanReportSchema.safeParse(v1Report);
    expect(parsedV1.success).toBe(true);

    // Phase 3 v1.1 report with byReachability
    const v11Report = {
      ...v1Report,
      schemaVersion: '1.1' as const,
      summary: {
        ...v1Report.summary,
        byReachability: {
          REACHABLE_CALL_PATH: 0,
          REACHABLE_IMPORT: 2,
          UNREACHABLE: 1,
          UNKNOWN: 0,
        },
      },
    };

    const parsedV11 = Contracts.ScanReportSchema.safeParse(v11Report);
    expect(parsedV11.success).toBe(true);
    if (parsedV11.success) {
      expect(parsedV11.data.schemaVersion).toBe('1.1');
      expect(parsedV11.data.summary.byReachability?.REACHABLE_IMPORT).toBe(2);
    }
  });

  it('B11: Phase 4 AI Triage schemas, UserConfigSchema, and ScanReportSchema v1.2 (A1, A12)', () => {
    // 1. AiVerdictSchema
    expect(Contracts.AiVerdictSchema.safeParse('LIKELY_TRUE_POSITIVE').success).toBe(true);
    expect(Contracts.AiVerdictSchema.safeParse('LIKELY_FALSE_POSITIVE').success).toBe(true);
    expect(Contracts.AiVerdictSchema.safeParse('NEEDS_HUMAN_REVIEW').success).toBe(true);
    expect(Contracts.AiVerdictSchema.safeParse('INVALID_VERDICT').success).toBe(false);

    // 2. AiCitationSchema
    expect(
      Contracts.AiCitationSchema.safeParse({
        file: 'src/app.ts',
        line: 42,
        quote: 'const x = 1;',
      }).success
    ).toBe(true);
    expect(
      Contracts.AiCitationSchema.safeParse({
        file: 'src/app.ts',
        line: -1, // invalid negative line
        quote: 'x',
      }).success
    ).toBe(false);

    // 3. AiTriageSchema
    const validTriage = {
      verdict: 'LIKELY_FALSE_POSITIVE' as const,
      confidence: 'HIGH' as const,
      rationale: 'Input is validated by sanitize() on line 12 before sink.',
      citations: [{ file: 'src/app.ts', line: 12, quote: 'sanitize(input)' }],
      exploitabilityNotes: 'Not reachable with untrusted input.',
      model: 'claude-3-5-sonnet',
      promptVersion: '1.0.0',
      cached: false,
      consistency: { samples: 2, agreed: true },
      tokens: { in: 1200, out: 150 },
      injectionFlag: false,
    };
    expect(Contracts.AiTriageSchema.safeParse(validTriage).success).toBe(true);

    // 4. SuppressionReasonCodeSchema includes GATE3_LIKELY_FALSE_POSITIVE
    expect(
      Contracts.SuppressionReasonCodeSchema.safeParse('GATE3_LIKELY_FALSE_POSITIVE').success
    ).toBe(true);

    // 5. UserConfigSchema
    const userCfg = Contracts.UserConfigSchema.parse({
      enabled: true,
      provider: 'openai',
      model: 'gpt-4o',
      baseUrl: 'http://localhost:11434/v1',
      gate3: {
        mode: 'suppress',
        neverSuppressSeverities: ['CRITICAL'],
      },
    });
    expect(userCfg.enabled).toBe(true);
    expect(userCfg.provider).toBe('openai');
    expect(userCfg.gate3.mode).toBe('suppress');

    // 6. ScanReportSchema v1.2 with ai execution summary and byAiVerdict
    const v12Report = {
      schemaVersion: '1.2' as const,
      tool: { name: 'secureship', version: '0.1.0' },
      target: 'C:/dev/target',
      mode: 'FULL' as const,
      startedAt: new Date().toISOString(),
      durationMs: 1250,
      scanners: [
        {
          name: 'gitleaks' as const,
          status: 'SUCCESS' as const,
          durationMs: 350,
          rawFindingCount: 0,
        },
      ],
      findings: [],
      suppressed: [],
      summary: {
        totalRaw: 3,
        totalReported: 1,
        totalSuppressed: 2,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 3, SCA: 0, SECRET: 0, IAC: 0 },
        byReachability: {
          REACHABLE_CALL_PATH: 0,
          REACHABLE_IMPORT: 1,
          UNREACHABLE: 2,
          UNKNOWN: 0,
        },
        byAiVerdict: {
          LIKELY_TRUE_POSITIVE: 1,
          LIKELY_FALSE_POSITIVE: 2,
          NEEDS_HUMAN_REVIEW: 0,
        },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 0,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
          GATE2_UNREACHABLE: 0,
          GATE3_LIKELY_FALSE_POSITIVE: 2,
        },
      },
      ai: {
        provider: 'openai',
        model: 'gpt-4o',
        host: 'localhost:11434',
        deterministic: true,
        findingsConsidered: 3,
        findingsSent: 3,
        findingsSkipped: [{ reason: 'CREDENTIAL_CLASS', count: 1 }],
        tokensIn: 3600,
        tokensOut: 450,
        filesSent: ['src/app.ts'],
        truncatedSlices: 0,
        cacheHits: 1,
        warnings: [],
      },
      warnings: [],
    };
    const parsedV12 = Contracts.ScanReportSchema.safeParse(v12Report);
    expect(parsedV12.success).toBe(true);
    if (parsedV12.success) {
      expect(parsedV12.data.schemaVersion).toBe('1.2');
      expect(parsedV12.data.ai?.provider).toBe('openai');
      expect(parsedV12.data.summary.byAiVerdict?.LIKELY_FALSE_POSITIVE).toBe(2);
    }
  });
});
