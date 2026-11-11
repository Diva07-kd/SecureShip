import { describe, it, expect } from 'vitest';
import { Gate1Scope } from '../src/gates/gate1-scope.js';
import type { NormalizedFinding } from '@secureship/contracts';

describe('Gate1Scope & Secret Policy Unit Suite', () => {
  it('correctly classifies path segments and filters lookalikes', () => {
    // True test/mock paths
    expect(Gate1Scope.classifyPath('packages/core/test/auth.test.ts')).toBe('TEST_OR_MOCK');
    expect(Gate1Scope.classifyPath('tests/unit/runner.py')).toBe('TEST_OR_MOCK');
    expect(Gate1Scope.classifyPath('src/__tests__/app.spec.js')).toBe('TEST_OR_MOCK');
    expect(Gate1Scope.classifyPath('testdata/input.json')).toBe('TEST_OR_MOCK');
    expect(Gate1Scope.classifyPath('mocks/client.ts')).toBe('TEST_OR_MOCK');

    // Example & Doc paths
    expect(Gate1Scope.classifyPath('examples/quickstart/index.js')).toBe('EXAMPLE');
    expect(Gate1Scope.classifyPath('samples/demo.py')).toBe('EXAMPLE');
    expect(Gate1Scope.classifyPath('docs/architecture.md')).toBe('DOCUMENTATION');
    expect(Gate1Scope.classifyPath('documentation/guide.md')).toBe('DOCUMENTATION');

    // Lookalike paths (must NOT be tagged as test or docs)
    expect(Gate1Scope.classifyPath('contest/algorithm.ts')).toBe('PRODUCTION');
    expect(Gate1Scope.classifyPath('latest/release.ts')).toBe('PRODUCTION');
    expect(Gate1Scope.classifyPath('attestation/report.ts')).toBe('PRODUCTION');
    expect(Gate1Scope.classifyPath('protests/march.ts')).toBe('PRODUCTION');
    expect(Gate1Scope.classifyPath('doctor/check.ts')).toBe('PRODUCTION');
  });

  it('detects dummy placeholder values reliably', () => {
    expect(Gate1Scope.isPlaceholder('dummy_test_secret_12345')).toBe(true);
    expect(Gate1Scope.isPlaceholder('EXAMPLE_TOKEN_VALUE')).toBe(true);
    expect(Gate1Scope.isPlaceholder('changeme')).toBe(true);
    expect(Gate1Scope.isPlaceholder('xxxx-xxxx-xxxx')).toBe(true);
    expect(Gate1Scope.isPlaceholder('sample_key')).toBe(true);
    expect(Gate1Scope.isPlaceholder('0000000000')).toBe(true);
    expect(Gate1Scope.isPlaceholder('mock_credentials')).toBe(true);

    // Real-looking random secrets
    expect(Gate1Scope.isPlaceholder('AKIAIOSFODNN7EXAMPLE_REAL_HASH_123')).toBe(true); // contains EXAMPLE
    expect(Gate1Scope.isPlaceholder('ghp_9K8j7H6g5F4d3S2a1Z0x9C8v7B6n5M4l3K2j')).toBe(false);
  });

  it('Gate 1 Secret Policy: preserves provider-specific secret without placeholder in test directory', () => {
    const finding: NormalizedFinding = {
      id: 'f-1',
      fingerprint: 'a'.repeat(64),
      ruleId: 'aws-access-key-id',
      scannerName: 'gitleaks',
      category: 'SECRET',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'tests/unit/aws.test.ts',
        startLine: 10,
        endLine: 10,
        redactedSnippet: 'AKIA...[REDACTED]', // Non-placeholder snippet!
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'TEST_OR_MOCK',
      title: 'AWS Access Key Leaked',
      description: 'AWS Access Key ID detected',
      cweIds: ['CWE-798'],
      evidence: [
        {
          scannerName: 'gitleaks',
          scannerRuleId: 'aws-access-key-id',
          message: 'Found AWS key',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    const res = Gate1Scope.evaluate(finding, {
      enabled: true,
      keepProviderSecrets: true,
    });

    // Policy dictates: Provider secret without placeholder stays REPORTED at confidence MEDIUM!
    expect(res.shouldSuppress).toBe(false);
    expect(res.scopeTag).toBe('TEST_OR_MOCK');
    expect(finding.confidence).toBe('MEDIUM');
  });

  it('Gate 1 Secret Policy: suppresses provider secret when snippet is a known placeholder', () => {
    const finding: NormalizedFinding = {
      id: 'f-2',
      fingerprint: 'b'.repeat(64),
      ruleId: 'aws-access-key-id',
      scannerName: 'gitleaks',
      category: 'SECRET',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'tests/unit/aws.test.ts',
        startLine: 10,
        endLine: 10,
        redactedSnippet: 'const key = "dummy_test_key_xxxx";', // Obvious placeholder!
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'TEST_OR_MOCK',
      title: 'AWS Access Key Leaked',
      description: 'AWS Access Key ID detected',
      cweIds: ['CWE-798'],
      evidence: [
        {
          scannerName: 'gitleaks',
          scannerRuleId: 'aws-access-key-id',
          message: 'Found AWS key',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    const res = Gate1Scope.evaluate(finding, {
      enabled: true,
      keepProviderSecrets: true,
    });

    // Suppressed because it is an obvious placeholder dummy in test code
    expect(res.shouldSuppress).toBe(true);
    expect(res.suppressionReason).toBe('GATE1_TEST_OR_MOCK');
  });

  it('suppresses SAST findings in tests, docs, and examples with appropriate reason codes', () => {
    const makeFinding = (filePath: string): NormalizedFinding => ({
      id: 'f-3',
      fingerprint: 'c'.repeat(64),
      ruleId: 'sql-injection',
      scannerName: 'opengrep',
      category: 'SAST',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: { filePath, startLine: 5, endLine: 5 },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'SQL Injection',
      description: 'SQL Injection',
      cweIds: ['CWE-89'],
      evidence: [
        { scannerName: 'opengrep', scannerRuleId: 'sql-injection', message: 'SQL injection' },
      ],
      createdAt: new Date().toISOString(),
    });

    const testRes = Gate1Scope.evaluate(makeFinding('test/api.test.ts'));
    expect(testRes.shouldSuppress).toBe(true);
    expect(testRes.suppressionReason).toBe('GATE1_TEST_OR_MOCK');

    const docRes = Gate1Scope.evaluate(makeFinding('docs/tutorial.md'));
    expect(docRes.shouldSuppress).toBe(true);
    expect(docRes.suppressionReason).toBe('GATE1_DOCUMENTATION');

    const exRes = Gate1Scope.evaluate(makeFinding('examples/demo/app.ts'));
    expect(exRes.shouldSuppress).toBe(true);
    expect(exRes.suppressionReason).toBe('GATE1_EXAMPLE');
  });

  it('--include-nonproduction keeps all non-production findings reported', () => {
    const finding: NormalizedFinding = {
      id: 'f-4',
      fingerprint: 'd'.repeat(64),
      ruleId: 'xss',
      scannerName: 'opengrep',
      category: 'SAST',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: { filePath: 'test/component.test.ts', startLine: 1, endLine: 1 },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'XSS',
      description: 'XSS',
      cweIds: ['CWE-79'],
      evidence: [{ scannerName: 'opengrep', scannerRuleId: 'xss', message: 'XSS' }],
      createdAt: new Date().toISOString(),
    };

    const res = Gate1Scope.evaluate(finding, {
      includeNonProduction: true,
    });

    expect(res.shouldSuppress).toBe(false);
  });
});
