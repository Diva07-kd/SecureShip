import { describe, it, expect } from 'vitest';
import {
  ReachabilityEvidenceKindSchema,
  SymbolSourceSchema,
  SymbolUsageSiteSchema,
  SymbolDatasetMetadataSchema,
  ReachabilityEvidenceSchema,
  FunctionLevelSummarySchema,
  ScanReportSchema,
  UserReachabilityConfigSchema,
  UserConfigSchema,
} from '../src/index.js';

describe('Phase B Reachability Contracts (Deliverable 1)', () => {
  it('accepts new Phase B reachability evidence kinds', () => {
    const kinds = [
      'SYMBOL_REFERENCED',
      'SYMBOL_CALL_PATH',
      'UNINVOKED_SYMBOL',
      'NAMESPACE_ESCAPES',
      'SYMBOL_DATA_UNAVAILABLE',
    ];
    for (const kind of kinds) {
      expect(ReachabilityEvidenceKindSchema.parse(kind)).toBe(kind);
    }
  });

  it('validates symbol sources', () => {
    expect(SymbolSourceSchema.parse('STRUCTURED_ADVISORY')).toBe('STRUCTURED_ADVISORY');
    expect(SymbolSourceSchema.parse('CURATED_DB')).toBe('CURATED_DB');
    expect(SymbolSourceSchema.parse('HEURISTIC_TEXT')).toBe('HEURISTIC_TEXT');
    expect(() => SymbolSourceSchema.parse('INVALID_SOURCE')).toThrow();
  });

  it('validates symbol usage sites', () => {
    const valid = {
      file: 'src/app.ts',
      line: 42,
      form: 'member_call',
    };
    expect(SymbolUsageSiteSchema.parse(valid)).toEqual(valid);
    expect(() =>
      SymbolUsageSiteSchema.parse({ file: 'src/app.ts', line: -1, form: 'call' })
    ).toThrow();
  });

  it('validates symbol dataset metadata', () => {
    const valid = {
      id: 'secureship-symbols-v1',
      sourceUrls: ['https://github.com/advisories/GHSA-35jh-r3h4-6jhm'],
    };
    expect(SymbolDatasetMetadataSchema.parse(valid)).toEqual(valid);
  });

  it('validates ReachabilityEvidence with Phase B optional fields', () => {
    const evidence = {
      kind: 'UNINVOKED_SYMBOL' as const,
      symbols: ['template', 'templateSettings'],
      symbolSource: 'CURATED_DB' as const,
      usageSites: [{ file: 'src/index.ts', line: 10, form: 'import_binding' }],
      dataset: {
        id: 'secureship-symbols-v1',
        sourceUrls: ['https://github.com/advisories/GHSA-35jh-r3h4-6jhm'],
      },
      blockedBy: undefined,
    };
    const parsed = ReachabilityEvidenceSchema.parse(evidence);
    expect(parsed.kind).toBe('UNINVOKED_SYMBOL');
    expect(parsed.symbols).toEqual(['template', 'templateSettings']);
    expect(parsed.symbolSource).toBe('CURATED_DB');
    expect(parsed.usageSites).toHaveLength(1);
    expect(parsed.dataset?.id).toBe('secureship-symbols-v1');
  });

  it('caps usageSites at maximum 5 sites', () => {
    const sites = Array.from({ length: 6 }, (_, i) => ({
      file: `src/file${i}.ts`,
      line: i + 1,
      form: 'call',
    }));
    expect(() =>
      ReachabilityEvidenceSchema.parse({
        kind: 'SYMBOL_REFERENCED',
        usageSites: sites,
      })
    ).toThrow();
  });

  it('validates FunctionLevelSummary schema', () => {
    const summary = {
      evaluated: 10,
      noSymbolData: 2,
      symbolReferenced: 3,
      callPathProven: 1,
      uninvoked: 3,
      escapedOrUnknown: 1,
      skippedTier: 0,
      blockedByReason: {
        P4_DYNAMIC_IMPORT: 1,
      },
    };
    expect(FunctionLevelSummarySchema.parse(summary)).toEqual(summary);
  });

  it('validates ScanReportSchema with version 1.0, 1.1, 1.2, and 1.3', () => {
    const baseReport = {
      tool: { name: 'secureship', version: '1.0.0' },
      target: '.',
      mode: 'FULL' as const,
      startedAt: new Date().toISOString(),
      durationMs: 120,
      scanners: [],
      findings: [],
      suppressed: [],
      summary: {
        totalRaw: 0,
        totalReported: 0,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 0,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
          GATE2_UNREACHABLE: 0,
          GATE3_LIKELY_FALSE_POSITIVE: 0,
          SUPPLY_CHAIN_ALLOWLISTED: 0,
        },
      },
    };

    for (const v of ['1.0', '1.1', '1.2', '1.3'] as const) {
      const parsed = ScanReportSchema.parse({ ...baseReport, schemaVersion: v });
      expect(parsed.schemaVersion).toBe(v);
    }

    // Default schemaVersion should be 1.2 for backward compatibility
    const defaultParsed = ScanReportSchema.parse(baseReport);
    expect(defaultParsed.schemaVersion).toBe('1.2');
  });

  it('validates UserReachabilityConfig and UserConfig', () => {
    const parsed = UserConfigSchema.parse({
      reachability: {
        functionLevel: 'off',
        symbolDataset: '/custom/symbols.json',
      },
    });
    expect(parsed.reachability.functionLevel).toBe('off');
    expect(parsed.reachability.symbolDataset).toBe('/custom/symbols.json');

    const defaultParsed = UserConfigSchema.parse({});
    expect(defaultParsed.reachability.functionLevel).toBe('auto');
    expect(defaultParsed.reachability.symbolDataset).toBeUndefined();

    const reachabilityConfig = UserReachabilityConfigSchema.parse({ functionLevel: 'off' });
    expect(reachabilityConfig.functionLevel).toBe('off');
  });
});
