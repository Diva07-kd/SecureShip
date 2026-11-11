import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import _Ajv from 'ajv';
import _addFormats from 'ajv-formats';
import { SarifExporter } from '../src/report/sarif-exporter.js';
import type { ScanReport, Severity } from '@secureship/contracts';

// Dual CJS/ESM compatible resolver for Ajv in TypeScript NodeNext environments
const Ajv = ((_Ajv as unknown as { default?: new (...args: unknown[]) => unknown }).default ??
  _Ajv) as new (...args: unknown[]) => {
  compile: (schema: unknown) => { (data: unknown): boolean; errors?: unknown[] };
};
const addFormats = ((_addFormats as unknown as { default?: (ajv: unknown) => void }).default ??
  _addFormats) as (ajv: unknown) => void;

describe('SarifExporter Schema Validation Suite', () => {
  const schemaPath = path.resolve('schemas/sarif-schema-2.1.0.json');

  it('exports valid SARIF 2.1.0 that strictly satisfies official OASIS JSON schema', () => {
    expect(existsSync(schemaPath)).toBe(true);
    const schemaJson = JSON.parse(readFileSync(schemaPath, 'utf-8'));

    // Configure Ajv for SARIF 2.1.0 validation
    const ajv = new Ajv({
      strict: false,
      allErrors: true,
      validateSchema: false,
    });
    addFormats(ajv);
    const validate = ajv.compile(schemaJson);

    const sampleReport: ScanReport = {
      schemaVersion: '1.0',
      tool: { name: 'secureship', version: '0.1.0-alpha' },
      target: 'C:/dev/SecureShip-IDE',
      mode: 'FULL',
      startedAt: new Date().toISOString(),
      durationMs: 1200,
      scanners: [
        {
          name: 'opengrep',
          version: '1.0.0',
          status: 'SUCCESS',
          durationMs: 500,
          rawFindingCount: 1,
        },
      ],
      findings: [
        {
          id: 'f-1',
          fingerprint: '1234567890abcdef'.repeat(4),
          ruleId: 'secureship-js-eval',
          scannerName: 'opengrep',
          category: 'SAST',
          severity: 'CRITICAL',
          confidence: 'HIGH',
          reachability: 'UNKNOWN',
          location: {
            filePath: 'src/handler.ts',
            startLine: 15,
            endLine: 15,
            startColumn: 3,
            endColumn: 25,
            redactedSnippet: 'eval(userInput);',
          },
          upstreamValidationStatus: 'UNKNOWN',
          verificationStatus: 'UNVERIFIED',
          scopeTag: 'PRODUCTION',
          title: 'Dynamic Code Evaluation',
          description: 'eval() with non-literal input',
          cweIds: ['CWE-95'],
          evidence: [
            {
              scannerName: 'opengrep',
              scannerRuleId: 'secureship-js-eval',
              message: 'eval() with non-literal input',
            },
          ],
          createdAt: new Date().toISOString(),
        },
      ],
      suppressed: [
        {
          finding: {
            id: 'f-2',
            fingerprint: 'abcdef1234567890'.repeat(4),
            ruleId: 'mock-secret',
            scannerName: 'gitleaks',
            category: 'SECRET',
            severity: 'HIGH',
            confidence: 'LOW',
            reachability: 'UNREACHABLE',
            location: {
              filePath: 'test/mock.ts',
              startLine: 2,
              endLine: 2,
            },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'TEST_OR_MOCK',
            title: 'Mock secret',
            description: 'Mock secret',
            cweIds: [],
            evidence: [
              {
                scannerName: 'gitleaks',
                scannerRuleId: 'mock-secret',
                message: 'Mock secret in test',
              },
            ],
            createdAt: new Date().toISOString(),
          },
          reasonCode: 'GATE1_TEST_OR_MOCK',
          detail: 'Test code',
          source: 'Gate 1',
        },
      ],
      summary: {
        totalRaw: 2,
        totalReported: 1,
        totalSuppressed: 1,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 1, SCA: 0, SECRET: 0, IAC: 0 },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 1,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
        },
      },
      warnings: [],
    };

    // 1. Export without suppressions
    const sarifOutput = SarifExporter.export(sampleReport, { includeSuppressed: false });
    const parsedSarif = JSON.parse(sarifOutput);

    const valid = validate(parsedSarif);
    if (!valid) {
      console.error('SARIF Schema Validation Errors:', validate.errors);
    }
    expect(valid).toBe(true);
    expect(parsedSarif.runs[0].results).toHaveLength(1);

    // 2. Export with suppressions
    const sarifWithSuppressed = SarifExporter.export(sampleReport, { includeSuppressed: true });
    const parsedWithSup = JSON.parse(sarifWithSuppressed);
    const validWithSup = validate(parsedWithSup);
    expect(validWithSup).toBe(true);
    expect(parsedWithSup.runs[0].results).toHaveLength(2);
    expect(parsedWithSup.runs[0].results[1].suppressions).toBeDefined();
    expect(parsedWithSup.runs[0].results[1].suppressions[0].justification).toBe(
      'GATE1_TEST_OR_MOCK'
    );
  });

  it('maps all Severities to correct SARIF levels and CVSS scores', () => {
    expect(SarifExporter.toSarifLevel('CRITICAL')).toBe('error');
    expect(SarifExporter.toSarifLevel('HIGH')).toBe('error');
    expect(SarifExporter.toSarifLevel('MEDIUM')).toBe('warning');
    expect(SarifExporter.toSarifLevel('LOW')).toBe('note');
    expect(SarifExporter.toSarifLevel('INFO')).toBe('none');
    expect(SarifExporter.toSarifLevel('UNKNOWN' as unknown as Severity)).toBe('warning');

    expect(SarifExporter.toCvssScore('CRITICAL')).toBe('9.5');
    expect(SarifExporter.toCvssScore('HIGH')).toBe('8.0');
    expect(SarifExporter.toCvssScore('MEDIUM')).toBe('5.5');
    expect(SarifExporter.toCvssScore('LOW')).toBe('2.0');
    expect(SarifExporter.toCvssScore('INFO')).toBe('0.0');
    expect(SarifExporter.toCvssScore('UNKNOWN' as unknown as Severity)).toBe('5.0');
  });
});
