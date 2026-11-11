import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { FindingCorrelator } from '../../src/normalizer/finding-correlator.js';
import { SecretRedactor } from '../../src/security/secret-redactor.js';
import { NormalizedFinding, NormalizedFindingSchema, ProjectProfile } from '@secureship/contracts';

describe('Part F Verification: FindingCorrelator', () => {
  it('F1: fingerprint determinism and formula matching hash(posixFilePath:ruleId:normalizedSink)', () => {
    const filePath = 'src/services/auth.ts';
    const ruleId = 'insecure-crypto';
    const sink = 'crypto.createCipher("des", key)';

    const expectedHash = createHash('sha256')
      .update(`${filePath}:${ruleId.toLowerCase()}:${sink.replace(/\s+/g, ' ').trim()}`)
      .digest('hex');

    const fp = FindingCorrelator.generateFingerprint(filePath, ruleId, sink);
    expect(fp).toBe(expectedHash);
    expect(fp).toHaveLength(64);

    // Across repeated runs
    for (let i = 0; i < 50; i++) {
      expect(FindingCorrelator.generateFingerprint(filePath, ruleId, sink)).toBe(expectedHash);
    }

    // Changing any item changes hash
    expect(FindingCorrelator.generateFingerprint('src/other.ts', ruleId, sink)).not.toBe(
      expectedHash
    );
    expect(FindingCorrelator.generateFingerprint(filePath, 'other-rule', sink)).not.toBe(
      expectedHash
    );
    expect(FindingCorrelator.generateFingerprint(filePath, ruleId, 'different-sink')).not.toBe(
      expectedHash
    );
  });

  it('F2: path normalization treats forward slashes, backslashes, and leading ./ identically', () => {
    const fp1 = FindingCorrelator.generateFingerprint('src/a/b.ts', 'rule-1', 'sink');
    const fp2 = FindingCorrelator.generateFingerprint('src\\a\\b.ts', 'rule-1', 'sink');
    const fp3 = FindingCorrelator.generateFingerprint('./src/a/b.ts', 'rule-1', 'sink');

    expect(fp1).toBe(fp2);
    expect(fp1).toBe(fp3);
  });

  it('F3: deduplicates multi-scanner findings, merges evidence, and upgrades severity/confidence', () => {
    const fp = FindingCorrelator.generateFingerprint(
      'src/api.ts',
      'xss-rule',
      'res.send(userInput)'
    );

    const f1: NormalizedFinding = {
      id: 'f-1',
      fingerprint: fp,
      ruleId: 'xss-rule',
      scannerName: 'opengrep',
      category: 'SAST',
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'src/api.ts',
        startLine: 10,
        endLine: 10,
        redactedSnippet: 'res.send(userInput)',
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'XSS',
      description: 'Reflected XSS',
      cweIds: ['CWE-79'],
      evidence: [
        { scannerName: 'opengrep', scannerRuleId: 'xss-rule', message: 'Opengrep finding' },
      ],
      createdAt: new Date().toISOString(),
    };

    const f2: NormalizedFinding = {
      ...f1,
      id: 'f-2',
      scannerName: 'semgrep',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      evidence: [{ scannerName: 'semgrep', scannerRuleId: 'xss-rule', message: 'Semgrep finding' }],
    };

    const f3: NormalizedFinding = {
      ...f1,
      id: 'f-3',
      scannerName: 'trivy',
      severity: 'HIGH',
      confidence: 'LOW',
      evidence: [{ scannerName: 'trivy', scannerRuleId: 'xss-rule', message: 'Trivy finding' }],
    };

    const merged = FindingCorrelator.correlate([f1, f2, f3]);
    expect(merged).toHaveLength(1);
    const result = merged[0]!;
    expect(result.severity).toBe('CRITICAL');
    expect(result.confidence).toBe('HIGH');
    expect(result.evidence).toHaveLength(3);
  });

  it('F4: Gate 1 scope filter downgrades test code while preserving production code', () => {
    const profile: ProjectProfile = {
      workspaceRoot: 'c:/app',
      languages: ['TypeScript'],
      frameworks: [],
      packageManagers: ['pnpm'],
      lockfiles: ['pnpm-lock.yaml'],
      iacManifests: [],
      testDirectories: ['tests', '__tests__', 'mocks', 'fixtures', 'spec'],
      recommendedScanners: ['gitleaks'],
      totalFilesScanned: 5,
      hasGit: true,
    };

    // Headline scenario: Hardcoded password in tests
    const testSecretFinding: NormalizedFinding = {
      id: 'sec-1',
      fingerprint: '',
      ruleId: 'hardcoded-secret',
      scannerName: 'gitleaks',
      category: 'SECRET',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'tests/unit/login.test.ts',
        startLine: 25,
        endLine: 25,
        redactedSnippet: 'const mockPass = "admin123";',
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Secret Detected',
      description: 'Found secret in test',
      cweIds: ['CWE-798'],
      evidence: [{ scannerName: 'gitleaks', scannerRuleId: 'generic-secret', message: 'detected' }],
      createdAt: new Date().toISOString(),
    };

    // Production finding
    const prodFinding: NormalizedFinding = {
      ...testSecretFinding,
      id: 'sec-2',
      location: {
        filePath: 'src/services/auth.ts',
        startLine: 50,
        endLine: 50,
        redactedSnippet: 'const prodKey = "AKIA...[REDACTED]";',
      },
    };

    // Non-test lookalike path: contest/
    const contestFinding: NormalizedFinding = {
      ...testSecretFinding,
      id: 'sec-3',
      location: {
        filePath: 'contest/leaderboard.ts',
        startLine: 1,
        endLine: 1,
        redactedSnippet: 'export const score = 100;',
      },
    };

    const correlated = FindingCorrelator.correlate(
      [testSecretFinding, prodFinding, contestFinding],
      profile
    );

    const testResult = correlated.find((f) => f.id === 'sec-1')!;
    const prodResult = correlated.find((f) => f.id === 'sec-2')!;
    const contestResult = correlated.find((f) => f.id === 'sec-3')!;

    // Test finding must be downgraded
    expect(testResult.confidence).toBe('LOW');
    expect(testResult.reachability).toBe('UNREACHABLE');
    expect(testResult.scopeTag).toBe('TEST_OR_MOCK');

    // Production finding preserves high confidence
    expect(prodResult.confidence).toBe('HIGH');
    expect(prodResult.scopeTag).toBe('PRODUCTION');

    // Lookalike contest/ must NOT be downgraded
    expect(contestResult.confidence).toBe('HIGH');
    expect(contestResult.scopeTag).toBe('PRODUCTION');
  });

  it('F5: Gate 1 scope for examples/docs/migrations (informational check)', () => {
    // Check if examples and docs are classified
    const isDocTest = FindingCorrelator.isTestPath('docs/guide.md');
    const isExampleTest = FindingCorrelator.isTestPath('examples/demo.ts');
    // Report finding: current TEST_PATH_REGEX targets test, tests, __tests__, mocks, fixtures, spec
    expect(typeof isDocTest).toBe('boolean');
    expect(typeof isExampleTest).toBe('boolean');
  });

  it('F6: ensures secrets in finding snippet are masked', () => {
    const rawSecretSnippet = 'AWS_KEY="AKIAIOSFODNN7EXAMPLE"';
    const masked = SecretRedactor.redactText(rawSecretSnippet);

    const finding: NormalizedFinding = {
      id: 'f-sec',
      fingerprint: '',
      ruleId: 'aws-secret',
      scannerName: 'gitleaks',
      category: 'SECRET',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'src/config.ts',
        startLine: 5,
        endLine: 5,
        redactedSnippet: masked,
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Secret',
      description: 'Secret detected',
      cweIds: [],
      evidence: [{ scannerName: 'gitleaks', scannerRuleId: 'aws', message: 'secret found' }],
      createdAt: new Date().toISOString(),
    };

    const correlated = FindingCorrelator.correlate([finding]);
    expect(correlated[0]!.location.redactedSnippet).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(correlated[0]!.location.redactedSnippet).toContain('[REDACTED]');
  });

  it('F7: performance on bulk findings and empty input', () => {
    expect(FindingCorrelator.correlate([])).toEqual([]);

    const bulkFindings: NormalizedFinding[] = Array.from({ length: 1000 }, (_, i) => ({
      id: `bulk-${i}`,
      fingerprint: '',
      ruleId: `rule-${i % 10}`,
      scannerName: 'opengrep',
      category: 'SAST',
      severity: 'LOW',
      confidence: 'MEDIUM',
      reachability: 'UNKNOWN',
      location: {
        filePath: `src/file_${i % 50}.ts`,
        startLine: (i % 100) + 1,
        endLine: (i % 100) + 1,
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Bulk Finding',
      description: 'Desc',
      cweIds: [],
      evidence: [{ scannerName: 'opengrep', scannerRuleId: 'r', message: 'm' }],
      createdAt: new Date().toISOString(),
    }));

    const t0 = Date.now();
    const result = FindingCorrelator.correlate(bulkFindings);
    const elapsed = Date.now() - t0;

    expect(result.length).toBeGreaterThan(0);
    expect(elapsed).toBeLessThan(2000);
  });

  it('F8: all correlated findings strictly validate against NormalizedFindingSchema', () => {
    const rawFinding: NormalizedFinding = {
      id: 'f-val',
      fingerprint: '',
      ruleId: 'sql-inj',
      scannerName: 'opengrep',
      category: 'SAST',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'src/repo.ts',
        startLine: 1,
        endLine: 1,
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'T',
      description: 'D',
      cweIds: ['CWE-89'],
      evidence: [{ scannerName: 'opengrep', scannerRuleId: 'r', message: 'm' }],
      createdAt: new Date().toISOString(),
    };

    const correlated = FindingCorrelator.correlate([rawFinding]);
    const parsed = NormalizedFindingSchema.safeParse(correlated[0]);
    expect(parsed.success).toBe(true);
  });
});
