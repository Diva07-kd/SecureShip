import { describe, it, expect } from 'vitest';
import { FindingCorrelator } from '../src/normalizer/finding-correlator.js';
import { NormalizedFinding, ProjectProfile } from '@secureship/contracts';

describe('FindingCorrelator', () => {
  it('should generate deterministic fingerprints regardless of path slashes or snippet whitespace', () => {
    const fp1 = FindingCorrelator.generateFingerprint(
      'src/controllers/user.ts',
      'sql-injection-rule',
      'SELECT * FROM users WHERE id = ' + 'input'
    );

    const fp2 = FindingCorrelator.generateFingerprint(
      'src\\controllers\\user.ts',
      'sql-injection-rule',
      'SELECT * FROM users WHERE id =    input'
    );

    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64); // SHA-256 length
  });

  it('should deduplicate findings from multiple scanners and merge evidence', () => {
    const fp = FindingCorrelator.generateFingerprint('src/db.ts', 'sqli-rule', 'rawQuery(input)');

    const finding1: NormalizedFinding = {
      id: 'f-1',
      fingerprint: fp,
      ruleId: 'sqli-rule',
      scannerName: 'opengrep',
      category: 'SAST',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'src/db.ts',
        startLine: 42,
        endLine: 42,
        redactedSnippet: 'rawQuery(input)',
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'SQL Injection in rawQuery',
      description: 'User input concatenation',
      cweIds: ['CWE-89'],
      evidence: [
        {
          scannerName: 'opengrep',
          scannerRuleId: 'sqli-rule',
          message: 'Potential SQL injection detected by opengrep',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    const finding2: NormalizedFinding = {
      id: 'f-2',
      fingerprint: fp,
      ruleId: 'sqli-rule',
      scannerName: 'semgrep',
      category: 'SAST',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'src/db.ts',
        startLine: 42,
        endLine: 42,
        redactedSnippet: 'rawQuery(input)',
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'SQL Injection in rawQuery',
      description: 'User input concatenation',
      cweIds: ['CWE-89'],
      evidence: [
        {
          scannerName: 'semgrep',
          scannerRuleId: 'sqli-rule',
          message: 'Confirmed SQL injection by semgrep',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    const merged = FindingCorrelator.correlate([finding1, finding2]);

    expect(merged).toHaveLength(1);
    const result = merged[0]!;
    expect(result.severity).toBe('CRITICAL'); // Upgraded to highest
    expect(result.confidence).toBe('HIGH');
    expect(result.evidence).toHaveLength(2); // Both scanner evidence preserved
    expect(result.evidence.map((e) => e.scannerName)).toEqual(['opengrep', 'semgrep']);
  });

  it('should apply Gate 1 Scope Filter: downgrade confidence to LOW and set UNREACHABLE for test files', () => {
    const mockProfile: ProjectProfile = {
      workspaceRoot: 'c:/repo',
      languages: ['TypeScript'],
      frameworks: [],
      packageManagers: ['pnpm'],
      lockfiles: ['pnpm-lock.yaml'],
      iacManifests: [],
      testDirectories: ['tests', '__mocks__'],
      recommendedScanners: ['opengrep'],
      totalFilesScanned: 10,
      hasGit: true,
    };

    const testFinding: NormalizedFinding = {
      id: 'test-f-1',
      fingerprint: '',
      ruleId: 'hardcoded-credentials',
      scannerName: 'gitleaks',
      category: 'SECRET',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      reachability: 'REACHABLE_CALL_PATH',
      location: {
        filePath: 'tests/unit/auth.test.ts',
        startLine: 15,
        endLine: 15,
        redactedSnippet: 'const fakePassword = "password123";',
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Hardcoded Password Found',
      description: 'Found password in test file',
      cweIds: ['CWE-798'],
      evidence: [
        {
          scannerName: 'gitleaks',
          scannerRuleId: 'generic-api-key',
          message: 'Secret detected',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    const results = FindingCorrelator.correlate([testFinding], mockProfile);

    expect(results).toHaveLength(1);
    const correlated = results[0]!;
    // Gate 1 should downgrade confidence and tag as test scope
    expect(correlated.confidence).toBe('LOW');
    expect(correlated.reachability).toBe('UNREACHABLE');
    expect(correlated.scopeTag).toBe('TEST_OR_MOCK');
  });
});
